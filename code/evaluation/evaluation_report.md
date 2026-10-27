Sample requests: 32
Status accuracy: 32/32 = 1.0000
Exact step-array match: 32/32 = 1.0000
Exact sequence (step fields, status excluded): 32/32 = 1.0000
Step signatures: predicted=193, reference=193, matched=193
Step precision=1.0000, recall=1.0000, F1=1.0000
Missing reference steps=0; extra predicted steps=0
Field accuracy at paired sequence positions:
phase: 193/193 = 1.0000
system\_id: 193/193 = 1.0000
resource\_id: 193/193 = 1.0000
operation: 193/193 = 1.0000
state: 193/193 = 1.0000
evidence\_id: 193/193 = 1.0000
Status confusion:
reference=COMPLETE predicted=COMPLETE: 10
reference=INCOMPLETE predicted=INCOMPLETE: 22
Synthetic tests:
PASS: password reset is not deletion
PASS: historical email alias resolves to stable identity
PASS: retained support record with no direct identifiers is redacted
PASS: enabled connector is an active data flow
PASS: backup with restore allowed is a restore risk
PASS: negated deletion remains not applicable
PASS: marketing-only removal is not account deletion

## Additional Test Cases



The reported synthetic tests cover these scenarios:



1\. Password reset is not deletion.

2\. Historical email alias resolves to a stable identity.

3\. A retained support record with no direct identifiers is redacted.

4\. An enabled connector is treated as an active data flow.

5\. A backup that permits restoration is treated as a restore risk.

6\. A negated deletion request is not applicable.

7\. A marketing-only removal request is not account deletion.



All seven tests are reported as passing.



\## Failures and Limitations



\- No mismatches were reported for the 32 public sample requests.

\- No failures were reported for the seven listed synthetic tests.

\- The public sample evaluation does not establish correctness across all 518 requests.

\- Hidden evaluation accuracy has not been measured in this report.



\## Improvements



The test suite checks request intent, historical identity resolution, retained-record redaction, active data flows, restore risks, and non-deletion requests. Further improvements should be based on reproducible failures found during full-dataset review and evaluation.

