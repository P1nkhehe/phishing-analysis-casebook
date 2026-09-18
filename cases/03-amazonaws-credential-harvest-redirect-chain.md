<span style="color:#d33">*This entire template is a Claude draft — copy it for each new case and edit freely.*</span>

# Case 03 - AWS typosquatting: Credential Harvester

| | |
|---|---|
| **Verdict** | Malicious (Phishing) |
| **Severity** | High - Direct brand imitation of a well known cloud service provider (aws.amazon) via typosquatting. |
| **Type** | Credential harvest |
| **Sample** | `https://phishtank.org/phish_detail.php?phish_id=9526640&frame=details` |
| **MITRE ATT&CK** | T1566.002 - Spearphishing Link|

![PhishTank Result](../images/case03-01-PhishTank-Result)

## 1. Summary

A phishing link copying the domain of a legitimate cloud service provider through the use of typosquatting. The illegitimate domain `https://aws-support-cloud[.]com/cp[.]php` tricks user by masking itself as amazons cloud support website from the link to the UI that aims to harvest user-credentials. 

## 2. URL & Domain Analysis

### URL breakdown

| Component | Value |
|---|---|
| Full URL (defanged) | `hxxps://aws-support-cloud[.]com/cp[.]php` |
| Domain | `aws-support-cloud[.]com` |
| Path | `/cp.php` |
| Typosquatting target | `aws.amazon.com` (Amazon Web Services) |
| Technique | Combosquatting - appending "support" and "cloud" to the brand name |

### Initial findings and observations

The link itself looks legitimate enough to trick someone who is not familiar with the real url or domain of aws is. 

Through the use and combination of `cloud` and `support` on the fake domain, attackers are able to fool the untrained eye. 

![Fake Domain Security Check Interface](../images/case03-02-fake-domain-screenshot)

Along with the believable url, the website interface also mimics the verification interface of an actual aws portal. 

This is why as users we should be cautious and observant when clicking any link as attackers can take advantage of our ignorance.

### Domain registration (WHOIS)

| Field | Value |
|---|---|
| Registrar | NameSilo, LLC |
| Registered | 2026-09-16T22:02:06Z |
| Domain age | < 48 hours old at time of PhishTank submission |
| Expires | 2027-09-16T22:02:06Z  |
| Registrant | Privacy-protected — identity unknown |
| Country | Unknown — registrant privacy enabled |
| Domain Status | **clientHold** |
| Name Servers | NS1/2/3.OPENPROVIDER.NL/.BE/.EU (Dutch/European hosting) |

![Results of WHOIS](../images/case03-03-WHOIS-results)

Let's analyze the results we got from using whois on the fake domain.

Starting with the registrar: NameSilo, a legitimate registrar. 

However, in recent investigations from `https://phishdestroy.io/namesilo-evidence` NameSilo has been associated with 5,666 confirmed phishing domains across a registrar with 5.25 million total registrations.

Although a legitimate Registrar the data tells us that attackers make use of the reputation of real Registrars to further add credibility to their phishing attacks.

Moving forward to the Registered date of the domain, the domain age, and the expiration date. All of these field present us with 1 thing, that the domain is a throwaway domain purely created for phishing purposes.

Legitimate domains such as the aws platform they are trying to imitate have been registered for a long amount of time, same thing can be said for the domain age and expiration date.

Now moving toward the status of the domain **clientHold**; this tells us that the domain has already been suspended by the registrar (NameSilo) possibly due to receiving an abuse report.
## 3. Sender validation

- Sender IP checked against the domain's SPF record: match / no match
- Domain MX records: present / absent
- Is the sending infrastructure shared (Google, Microsoft 365, a bulk provider)? If so, blacklist hits may not be attributable to this sender.

## 4. Reputation

| Indicator | VirusTotal | MXToolbox blacklist | Talos / AbuseIPDB |
|---|---|---|---|
| Sender domain | | | |
| Sender IP | | | |
| Reply-To domain | | | |

## 5. Content analysis

What does the email ask the recipient to do? Note: brand impersonation, urgency, financial or credential ask, mismatch between claimed organisation and actual sending domain, generic greeting, grammar.

## 6. Payload

- **Links:** extracted and defanged; urlscan.io / VirusTotal results; redirect chain if any
- **Attachments:** filename, type, SHA-256, VirusTotal / sandbox verdict — *never executed*
- **Callback numbers:** listed as IOCs

## 7. Verdict & reasoning

Why this verdict, in analyst terms. Address any contradictory signals (e.g. auth passes but content is malicious) and explain them.

## 8. Indicators of Compromise

| Type | Value (defanged) | Context |
|---|---|---|
| Email | | From / Reply-To |
| Domain | | |
| IPv4 | | sender IP |
| URL | `hxxp://` | |
| Phone | | callback lure |
| File hash | | .eml sample |

## 9. MITRE ATT&CK

| ID | Technique | How it applies |
|---|---|---|
| | | |

## 10. Recommended actions

1. Block sender address / domain at the mail gateway
2. Search and purge from all mailboxes (scope by Subject, sender, Message-ID)
3. Add IOCs to blocklists
4. Report abuse to the hosting / mail provider where infrastructure is compromised
5. User awareness note if appropriate

## Evidence

Screenshots referenced above.
