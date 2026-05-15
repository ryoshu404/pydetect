# AWS Valid Account Abuse EC2

## Threat Model

This rule detects EC2 instance roles being used from source IP addresses outside AWS infrastructure. This technique maps to T1078.004 (Valid Accounts: Cloud Accounts). Attackers can attempt to gain full access of the AWS the account. Per Elastic,a "successful login of this type is rare and high-risk, as it strongly suggests credential theft or unauthorized session hijacking"

This rule detects AWS EC2 instance role credentials being used from source IP addresses outside AWS infrastructure. This technique maps to MITRE ATT&CK T1078.004 (Valid Accounts: Cloud Accounts). When an EC2 instance is compromised, attackers retrieve temporary STS credentials from the Instance Metadata Service (IMDS) and use them externally to enumerate AWS resources, access S3 buckets, exfiltrate data, or pivot to other AWS services within the role's permission scope.

## Modality Choice

CloudTrail is the only AWS telemetry layer that captures API-call-level identity context at the moment of credential use. For this rule, `userIdentity.type` was used to detect instance roles, `userIdentity.principalId` for `':i-'` to distinguish EC2 instances. `sourceIPAddress` is used to filter for internal activity.

## FP Considerations

EC2 instances may be configured to use non-standard amazonaws.com domains, but in this scenario, the rule can be tuned by replacing or adding to the detection filter `filter_aws_internal`.

## Environmental Assumptions

This dataset and ruleset utilizes a mix of CloudTrail managementEvents and CloudTrail data events, which are not enabled by default. However, managementEvents are enabled by default and will also catch this activity.

## Source / Validation

The following articles were used in making this rule:

https://www.elastic.co/guide/en/security/8.19/aws-ec2-instance-console-login-via-assumed-role.html

https://www.ilyakobzar.com/p/ec2-iam-role-sts-credentials-compromise

The OTRF Dataset for AWS Cloud Bank Breach S3 was used to validate:

https://securitydatasets.com/notebooks/atomic/aws/initial_access/SDAWS-200914011940.html

The rule fires on 11 of 11 events that show this behavior, spanning multiple event types. As a note, the dataset is considerably small (103 events). The dataset's small size and attack-focused composition means every event in the dataset is malicious, so the rule's filter against legitimate EC2 instance role usage (the `filter_aws_internal` clause) isn't directly validated against benign baseline traffic.
