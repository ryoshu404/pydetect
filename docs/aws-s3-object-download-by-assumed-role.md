# AWS S3 Object Download By Assumed Role

## Threat Model

This rule detects S3 `GetObject` calls by assumed-role identities originating from source IP addresses outside AWS infrastructure, indicating potential data exfiltration of S3 objects following credential compromise. It maps to T1530 (Data from Cloud Storage). This rule is scoped to assumed-role identities to pair with the AWS Valid Account Abuse EC2 rule (T1078.004), where this rule catches the S3 exfiltration consequence of credential theft by the aforementioned rule.

## Modality Choice

CloudTrail is the only AWS telemetry layer that captures the data event `GetObject` utilized for this detection. `eventSource` and `eventName` are used in conjunction to observe `GetObject` performed on the S3 bucket.

## FP Considerations

Even with the external-IP filter, this rule has a high expected FP rate. Legitimate users downloading from S3 via assumed-role credentials from any non-AWS network (offices, home, developer laptops, CI/CD systems) will trigger it. Recommendation is to correlate with AWS Valid Account Abuse EC2 rule, and use this to see collection activity specifically, hence why medium was the assigned level in the Sigma rule.

## Environmental Assumptions

Data events must be enabled in CloudTrail as `GetObject` is classified as one.

## Source / Validation

The following articles were used in making this rule:

https://research.splunk.com/cloud/e4384bbf-5835-4831-8d85-694de6ad2cc6/

https://www.detectionatscale.com/p/correlating-aws-s3-breaches

https://attack.mitre.org/techniques/T1530/

The OTRF Dataset for AWS Cloud Bank Breach S3 was used to validate:

https://securitydatasets.com/notebooks/atomic/aws/initial_access/SDAWS-200914011940.html

The rule fires on exactly 2 events in the dataset (indices 79 and 102) which are both `GetObject` calls on `ring.txt` by the compromised assumed-role session from the external IP. The dataset's small size (103 events) and attacker-focused composition mean baseline benign traffic isn't represented; the rule's FP profile in production is research-grounded but not dataset-validated.
