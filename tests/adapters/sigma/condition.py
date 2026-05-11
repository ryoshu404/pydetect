"""Sigma condition expression parser and evaluator.

AST node shapes (returned by parser functions):
- ("identifier", "name")
- ("not", subtree)
- ("and", left, right)
- ("or", left, right)
- ("of_pattern", count, "pattern")  # count is "1" or "all"

Recursive descent parser; precedence (loosest to tightest):
or > and > not > atom (identifier / paren-group / quantifier)
"""

from __future__ import annotations

import re

from tests.adapters.sigma.modifiers import wildcard_to_regex


class _TokenStream:
    """Helper for the parser. Tracks position in a token list with peek/consume operations."""

    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.position = 0

    def peek(self) -> str | None:
        if self.position < len(self.tokens):
            return self.tokens[self.position]
        return None

    def consume(self) -> str:
        token = self.peek()
        if token is None:
            raise ValueError("Unexpected end of condition expression")
        self.position += 1
        return token

    def expect(self, expected: str) -> None:
        actual = self.peek()
        if actual != expected:
            raise ValueError(f"Expected '{expected}', got '{actual}' at position {self.position}")
        self.consume()

def evaluate_condition(condition: str, selection_results: dict[str, bool]) -> bool:
    tokens = _tokenize(condition)
    tree = _parse(tokens)
    return _evaluate_tree(tree, selection_results)


def _tokenize(condition: str) -> list[str]:
    # matches "(", ")", or any run of non-whitespace, non-paren characters
    return re.findall(r"\(|\)|[^\s()]+", condition)


def _parse(tokens: list[str]) -> object:
    """Parse tokens into a syntax tree. Returns the root node."""
    stream = _TokenStream(tokens)
    tree = _parse_or(stream)
    if stream.peek() is not None:
        raise ValueError(...)
    return tree

def _parse_or(stream):
    """Parse OR-level expression. Delegates to _parse_and for operands."""
    left = _parse_and(stream)
    while stream.peek() == "or":
        stream.consume()
        right = _parse_and(stream)
        left = ("or", left, right)
    return left

def _parse_and(stream):
    """Parse AND-level expression. Delegates to _parse_not for operands."""
    left = _parse_not(stream)
    while stream.peek() == "and":
        stream.consume()
        right = _parse_not(stream)
        left = ("and", left, right)
    return left

def _parse_not(stream):
    """Parse NOT-level expression. Unary; delegates to _parse_atom for operand."""
    next_token = stream.peek()
    if next_token == "not":
        stream.consume()
        operand = _parse_atom(stream)
        return ("not", operand)
    return _parse_atom(stream)

def _parse_atom(stream):
    """Parse atom: identifier, parenthesized expression, or 'x of pattern' quantifier."""
    next_token = stream.peek()
    if next_token == "(":
        stream.consume()
        tree = _parse_or(stream)
        stream.expect(")")
        return tree
    elif next_token in ("1", "all"):
        count = stream.consume()
        stream.expect("of")
        pattern = stream.consume()
        return ("of_pattern", count, pattern)
    else:
        return ("identifier", stream.consume())

def _evaluate_tree(tree, selection_results):
    match tree:
        case ("identifier", name):
            return selection_results[name]
        case ("not", subtree):
            return not _evaluate_tree(subtree, selection_results)
        case ("and", left, right):
            return _evaluate_tree(left, selection_results) and _evaluate_tree(right, selection_results)
        case ("or", left, right):
            return _evaluate_tree(left, selection_results) or _evaluate_tree(right, selection_results)
        case ("of_pattern", count, pattern):
            matched_names = _expand_pattern(pattern, selection_results)
            results = [selection_results[name] for name in matched_names]
            if count == "1":
                return any(results)
            if count == "all":
                return all(results)
            raise ValueError(f"Invalid count in of_pattern: {count}")
        case _:
            raise ValueError(f"Unknown tree node shape: {tree}")


def _expand_pattern(pattern: str, selection_results: dict[str, bool]) -> list[str]:
    regex_pattern = wildcard_to_regex(pattern)
    matched = []
    for name in selection_results:
        if name.startswith("_"):
            continue
        if re.fullmatch(regex_pattern, name):
            matched.append(name)
    return matched
