# Incident Response Runbook: Exposed AWS Credentials

**Runbook generated:** 2026-07-13T15:00:00Z
**Finding ID:** 50eedf6c-a691-4467-b4eb-b7bfa11aac0a
**Severity:** CRITICAL
**Status:** open

## 1. Finding Summary

- **Title:** IAM access key exposed in public GitHub repository
- **Description:** An active AWS access key belonging to prod-payments-api was found committed to a public source code repository. The key has not been rotated since detection and may permit unauthorized API access.
- **Affected resource:** `arn:aws:awsiamaccesskey:::prod-payments-api-334` (AwsIamAccessKey)
- **AWS account:** 123456789012 | **Region:** us-east-1
- **Detected:** 2026-06-22T14:56:41 (21 days open)
- **Source:** SecurityHub (mock)

## 2. Immediate Containment Steps

1. **Deactivate the exposed access key immediately** — do not wait for
   root-cause analysis to complete first:
   ```
   aws iam update-access-key --access-key-id <KEY_ID> --status Inactive --user-name <USER_NAME>
   ```
2. Search CloudTrail for any API activity using this key in the last 90 days
   to identify potential unauthorized use:
   ```
   aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<KEY_ID>
   ```
3. If any unrecognized or suspicious activity is found, escalate to the
   incident commander and treat this as a confirmed compromise, not a
   configuration issue — proceed to full IR process.
4. Notify the resource/account owner and the SecOps on-call channel.

## 3. Root Cause Investigation Steps

1. Identify where the credential was exposed (public repo, log file,
   container image, CI/CD artifact, Slack message, etc.).
2. Determine how long the credential had been exposed prior to detection,
   and cross-reference with the CloudTrail activity from step 2.
3. Review the permissions attached to the compromised identity to scope
   the blast radius (what could an attacker have done with this key?).
4. Determine whether the exposure was a one-off human error or indicates a
   systemic gap (e.g. missing pre-commit secret scanning, credentials
   baked into AMIs/containers).

## 4. Remediation Procedure

1. **Delete** the exposed access key entirely (not just deactivate) once
   containment is confirmed complete:
   ```
   aws iam delete-access-key --access-key-id <KEY_ID> --user-name <USER_NAME>
   ```
2. Issue a new credential through the approved secrets-management path
   (e.g. AWS Secrets Manager, Vault) — never re-issue a long-lived static
   key for the same purpose if a role-based or short-lived alternative exists.
3. Purge the credential from the exposed location (rewrite git history if
   applicable, delete leaked logs/artifacts, invalidate cached copies).
4. If systemic gaps were identified in root cause, file a follow-up ticket
   to close them (e.g. enable `git-secrets` / GitHub secret scanning,
   remove hardcoded credentials from build artifacts).

## 5. Verification Steps

- [ ] Confirm the old access key no longer authenticates
      (`aws sts get-caller-identity` using the old key returns an error).
- [ ] Confirm no CloudTrail activity has occurred using the old key since deactivation.
- [ ] Confirm the new credential is stored only in the approved secrets manager.
- [ ] Confirm the exposure source has been purged and verified via a fresh scan.
- [ ] Update the vulnerability register status to `resolved` with resolution notes.

## 6. Lessons Learned Template

*To be completed by the responding analyst after remediation.*

- **What happened:**
- **Why it happened (root cause):**
- **What worked well in the response:**
- **What could be improved:**
- **Preventive action items (with owners and due dates):**

---
*Generated automatically by AWS Security Operations Monitor. This runbook
should be reviewed and adapted by a qualified analyst — it is a
starting point, not a substitute for judgment.*
