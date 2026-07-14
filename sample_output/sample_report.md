# Security Operations Report

**Generated:** 2026-07-13T14:57:05.443135Z
**Total open findings:** 18

## Summary by Severity

| Severity | Open Findings | Trend |
|---|---|---|
| CRITICAL | 2 | — |
| HIGH | 8 | — |
| MEDIUM | 8 | — |
| LOW | 0 | — |
| INFORMATIONAL | 0 | — |

## Findings by Resource Type

| Resource Type | Open Findings |
|---|---|
| AwsCloudTrailTrail | 4 |
| AwsEc2Volume | 4 |
| AwsIamRole | 3 |
| AwsIamAccessKey | 3 |
| AwsEc2SecurityGroup | 2 |
| AwsS3Bucket | 2 |

## SLA Aging Analysis

Findings are expected to be remediated within severity-based SLA windows (CRITICAL: 7d, HIGH: 14d, MEDIUM: 30d, LOW: 60d, INFORMATIONAL: 90d). **3 finding(s) currently breach their SLA window.**

| Finding | Severity | Days Open | SLA (days) | Resource |
|---|---|---|---|---|
| CloudTrail logging is disabled or not delivering logs | HIGH | 45 | 14 | `arn:aws:awscloudtrailtrail:::shared-services-vpc-370` |
| Security group allows unrestricted ingress on sensitive port | HIGH | 45 | 14 | `arn:aws:awsec2securitygroup:::reporting-warehouse-324` |
| IAM access key exposed in public GitHub repository | CRITICAL | 21 | 7 | `arn:aws:awsiamaccesskey:::prod-payments-api-334` |

## Oldest Open Findings

| Finding | Severity | Days Open | Status |
|---|---|---|---|
| CloudTrail logging is disabled or not delivering logs | HIGH | 45 | open |
| Security group allows unrestricted ingress on sensitive port | HIGH | 45 | open |
| IAM role has excessive administrative permissions | MEDIUM | 30 | open |
| EBS volume is not encrypted at rest | MEDIUM | 30 | open |
| IAM access key exposed in public GitHub repository | CRITICAL | 21 | open |

## Executive Summary

There are currently **2 critical** and **8 high** severity findings open. 3 finding(s) are past their remediation SLA and should be prioritized this cycle. See the Compliance Mapping section of the README for how these findings map to OSFI B-13, OWASP, and CIS control frameworks.
