---
id: COMP-GDPR-33
title: GDPR Article 33 - breach notification for EU trial participants
type: compliance
source: compliance
hosts: helix-clinical-trials-phi
summary: Unauthorised access to helix-clinical-trials-phi exposes EU participants' special-category health data, so the 72-hour GDPR Art. 33 notification clock to the lead supervisory authority starts when the breach is confirmed.
---
# GDPR Article 33 obligations (Helix Dynamics summary)

## Scope
The bucket `helix-clinical-trials-phi` contains records of EU clinical-trial participants (for example
`trials/HX-221/participants_eu.csv`). Health data is special-category personal data under GDPR Art. 9.

## Obligation
A personal-data breach must be notified to the lead supervisory authority **within 72 hours** of becoming aware of it,
unless it is unlikely to result in a risk to individuals. Exfiltration of health data is presumed high risk, so
data subjects must also be informed without undue delay (Art. 34).

## SOC actions
- Notify the Data Protection Officer (dpo@helixdyn.example) as soon as exfiltration is suspected, not when confirmed.
- Preserve CloudTrail data events and S3 server access logs for the affected prefixes.
- Record the time of awareness in the incident ticket: this starts the 72-hour clock.
