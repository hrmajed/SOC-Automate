---
id: COMP-HIPAA-BN
title: HIPAA Breach Notification Rule - US trial participants (PHI)
type: compliance
source: compliance
hosts: helix-clinical-trials-phi
summary: helix-clinical-trials-phi holds US participants' PHI; an impermissible disclosure is presumed a reportable HIPAA breach unless a documented four-factor risk assessment shows low probability of compromise.
---
# HIPAA Breach Notification (45 CFR 164.400-414)

## Scope
US participant records in `helix-clinical-trials-phi` are protected health information (PHI).

## Obligation
An impermissible acquisition or disclosure of PHI is presumed to be a breach unless a documented four-factor risk
assessment demonstrates a low probability that the PHI has been compromised. Individuals must be notified no later
than 60 days after discovery; breaches affecting 500+ residents of a state also require media and HHS notification.

## SOC actions
- Involve the Privacy Officer and Legal immediately.
- Determine exactly which objects were read (CloudTrail data events: GetObject keys and byte counts).
