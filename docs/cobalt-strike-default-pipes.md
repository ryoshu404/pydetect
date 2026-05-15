# Cobalt Strike Default Named Pipes

## Threat Model

This rule detects named pipe creation events matching Cobalt Strike default pipe-name patterns documented from the vendor blog listed below. This technique maps to MITRE ATT&CK T1071.002 (Application Layer Protocol: File Transfer Protocols). Cobalt Strike utilizes named pipes encapsulated in SMB for peer-to-peer communication, exchanging data between the beacon and sacrificial processes

## Modality Choice

The `pipe_created` logsource (Sysmon EID 17 and 18) is the direct telemetry for named-pipe creation events. The pipe name is captured in the event's `PipeName` field at the moment of creation or connection.

## FP Considerations

The patterns identified in the detection section are associated with Cobalt Strike. The following command was run on 3 Windows hosts (analysis VM, general desktop, remote desktop):
`[System.IO.Directory]::GetFiles("\\.\pipe\")`
It returned no pipes matching the detection patterns and research did not surface default Windows installations using these naming conventions. It is possible that some other software utilizes these naming conventions for their pipes, but it is highly unlikely.

Since the naming convention is commonly associated with Cobalt Strike, the rule is purposely broad with the `startswith`, to catch anything with the documented prefixes regardless of what their suffixes may be. In the event that more fine tuning is needed `PipeName|re` can be utilized for stricter matching based on the data found in the example dataset and the vendor blog.
- `PipeName|re: '^\\(MSSE-[a-zA-Z0-9_]+-server|(msagent|postex|status)_[a-zA-Z0-9_]+)'`

## Environmental Assumptions

This detection rule relies on sysmon logging Sysmon Event ID 17 and 18 which is Pipe created/connected.

## Source / Validation

The following articles were used in making this rule:

https://labs.withsecure.com/publications/detecting-cobalt-strike-default-modules-via-named-pipe-analysis

https://www.cobaltstrike.com/blog/learn-pipe-fitting-for-all-of-your-offense-projects

The OTRF Dataset for APT Simulator Cobalt Strike was used to validate:

https://securitydatasets.com/notebooks/atomic/windows/defense_evasion/SDWIN-210611210814.html

The rule fires on exactly 4 of 5 EID 17 events showing this behaviour. The fifth pipe event (\334485) is the output channel for a CS psexec_psh service installation captured separately by EID 7045 at index 2608. The rule correctly does not detect this pipe because it falls outside the documented default-pipe-name patterns.
