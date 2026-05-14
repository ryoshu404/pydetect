# LSASS Credential Access

## Threat Model

This rule detects suspicious process access to lsass.exe with high-privilege access masks associated with credential dumping tools including Mimikatz, ProcDump, and comsvcs.dll-based memory dumping. This technique maps to T1003.001 (OS Credential Dumping: LSASS Memory). This technique can harvest credentials and be used to conduct lateral movement.

## Modality Choice

The `process_access` logsource (Sysmon EID 10) is the direct telemetry layer for handle-open events. The `GrantedAccess` field records the access mask granted to the source process, which can be used as a signal depending on what rights are used to access lsass.exe. No other telemetry layer captures this access-mask signal at the moment of handle grant.

## FP Considerations

This rule is expected to have a high FP rate as written. AV/EDR products, security and monitoring tools, and legitimate system processes routinely access lsass.exe with high-privilege access masks during normal operation.

#### Tuning variants for production deployment:

**SourceImage allowlist** - exclude known legitimate accessors:

```yaml
  filter_legitimate:
      SourceImage|endswith:
          - '\MsMpEng.exe' #and more as needed
  condition: selection and not filter_legitimate
```

**CallTrace positive indicators** - narrow to specific dumping technique signatures:

```yaml
  selection:
      TargetImage|endswith: '\lsass.exe'
      GrantedAccess: ['0x1010', '0x1410', '0x1438', '0x143A', '0x1F0FFF']
      CallTrace|contains:
          - 'UNKNOWN'        # Reflective DLL injection (Mimikatz via PowerShell)
          - 'dbgcore.dll'    # ProcDump-style dumping
          - 'dbghelp.dll'    # ProcDump-style dumping
```

  The `UNKNOWN` indicator specifically catches the reflective-injection pattern observed in this dataset's Mimikatz access event.

## Environmental Assumptions

This detection rule relies on sysmon logging Sysmon Event ID 10 which is ProcessAccess

## Source / Validation

The following sources were used in making this rule:
- https://attack.mitre.org/detectionstrategies/DET0363/
- https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html

The OTRF dataset Empire Mimikatz LogonPasswords was used to validate:
- https://securitydatasets.com/notebooks/atomic/windows/credential_access/SDWIN-190518202151.html

The dataset contained 6,026 events. Of those, 272 had EventID 10 (Process Access). Filtering further to events where `TargetImage` contains `lsass.exe` yielded 4 candidate events. The rule fires on exactly 1, which is index 2450, GrantedAccess `0x1010` from `powershell.exe` with `UNKNOWN(0x...)` in CallTrace indicating reflective DLL injection (the canonical Empire/PowerSploit Mimikatz delivery pattern). The other 3 LSASS-access events (indices 817, 821, 4205) use lower-privilege masks (`0x1000`, `0x1000`, `0x2000`) from svchost.exe accessing LSASS via Local Session Manager and SysMain — legitimate Windows component activity. The mask-based discrimination is the rule's precision mechanism.
