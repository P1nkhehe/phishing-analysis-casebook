
# Case 03 - AWS Combosquatting: Credential Harvester

| | |
|---|---|
| **Verdict** | Malicious (Phishing) |
| **Severity** | High - Direct brand imitation of a well known cloud service provider (aws.amazon) via typosquatting. |
| **Type** | Credential harvest |
| **Sample** | `https://phishtank.org/phish_detail.php?phish_id=9526640&frame=details` |
| **MITRE ATT&CK** | T1598.003: Phishing for Information|

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

However, according to "PhishDestroy" `https://phishdestroy.io/namesilo-evidence` NameSilo has been associated with 5,666 confirmed phishing domains across a registrar with 5.25 million total registrations.

Although a legitimate Registrar the data tells us that attackers make use of the reputation of real Registrars to further add credibility to their phishing attacks.

Moving forward to the Registered date of the domain, the domain age, and the expiration date. All of these field present us with 1 thing, that the domain is a throwaway domain purely created for phishing purposes.

Legitimate domains such as the aws platform they are trying to imitate have been registered for a long amount of time, same thing can be said for the domain age and expiration date.

Now moving toward the status of the domain **clientHold**; this tells us that the domain has already been suspended by the registrar (NameSilo) possibly due to receiving an abuse report.


## 3. Domain & Infrastructure Validation.

- **Typosquatting Target**: `aws.amazon.com` - the attacker combined the words "aws", "support", and "cloud" creating the fake domain
  `aws-support-cloud[.]com` (combosquatting technique)
- **Domain age:** < 48 hours at time of PhishTank submission - strong indicator of throwaway phishing infrastructure
- **Domain status:** `clientHold` — already suspended by registrar at time of investigation.
- **Hosting infrastructure:** OpenProvider nameservers (NL/BE/EU) — European hosting for a domain impersonating a US cloud provider

## 4. Reputation

| Indicator | Value | VirusTotal | MXToolbox Blacklist | Notes |
|---|---|---|---|---|
| Domain | `aws-support-cloud[.]com` | 16/91 - Phishing & Malicious | clientHold (suspended) | Suspended by registrar at investigation time |
| Resolved IP | `45.74.61[.]10` | 8/89 - Phishing, Malicious, Malware| MAILSPIKE BL, MAILSPIKE Z, Spamhaus ZEN | Hosted on 69HOST LLC (AS205397) — dedicated hosting, blacklist hits directly attributable to this infrastructure |
| CDN IP | `151.101.129[.]155` | — | — | Fastly CDN — legitimate shared infrastructure, not attacker-controlled |
| urlscan.io | `aws-support-cloud[.]com` | No classification | — | Likely scanned post-suspension; domain non-resolving |


![Results of VirusTotal](../images/case03-04-virustotal-results)

![Results of VirusTotal categories](../images/case03-05-virustotal-categories)


Upon looking up the domain on VirusTotal we discover that 16 out of 91 security vendors flagged the typosquatted domain as either phishing or malicious.

We also viewed the details tab to see additional information regarding the phishing domain. And consistent to our findings virustotal along with its security vendors flagged the link under the category of phishing or fraud while also identifying the targeted brand as Amazon via phishtank.

Now when it comes to looking for the Resolved IP for the phishing domain we can use the results we obtained from urlscan.io. Which is great as currently we cant use nslookup on the site as it is down due to the `clientHold` status.

![Resolved IP from urlscan.io](../images/case03-06-urlscan-resolvedip)

Using this information we can use the Resolved IP we have and check its reputation through various tools.

![IP lookup from VirusTotal](../images/case03-07-virustotal-resolvedip)

Virustotal recorded 8/89 of its security vendors flagging the resolved IP of the domain as Phishing, Malware, Malicious, and Suspicious. Another additional information/evidence we can obtain from here is  the TLS certificate on this IP is **self signed** which is a huge red flag as this means that rather than getting its TLS from a trusted Certificate Authority (CA) the attacker just generated it themselves,.

![IP lookup from AbuseIPDB](../images/case03-08-abuseIPDB-resolvedip)

Upon looking up the Resolved IP Address of the phishing domain in abuse IPDB we get the information that the IP has been reported 46 times and further scrolling down we can see the reporters along with their comments as to why they reported the IP.

![IP lookup from AbuseIPDB](../images/case03-09-abuseIPDB-reporters)

Based from the reporters and their comments on the IP we can deduce that the IP has been previously existing and has been associated with many sites with the oldest records of reports dating 3 years ago. From the comments it appears that the IP has been mostly associated with phishing scams and impersonation with the recent report stating that it impersonated a bank which asks for all user credentials.

![IP blacklisted in mxlookup](../images/case03-10-mxlookup-IP)

On mxlookup we can identify that the IP is on the blacklist namely MAILSPIKE BL, MAILSPIKE Z, **Spamhaus ZEN**. The IP getting a hit on MAILSPIKE which is a list of spam/malicious IPs is already good evidence. But another strong evidence which backs this up is Spamhaus ZEN which is one of the most recognized and widely trusted blacklists in existence. The IP being listed in Spamhaus means that it has a well documented history of malicious activity, which we have seen from the AbuseIPDB with reports dating back 3 years ago.
> **Note:** urlscan.io's no-verdict is explained by the `clientHold` status -
> the domain was likely non-resolving at scan time, this is not an indicator that the site is legitimate.

## 5. Website Analysis
![Fake Domain Security Check Interface](../images/case03-02-fake-domain-screenshot)

*(Based on urlscan.io historical scan — page not visited directly)*

From the historical scan of the compromised page we can see that it leads us to a captcha page. Attackers didn't just use this without a reason, the likely reason for this is **Anti analysis/Evasion** so they can avoid automated scanners such as the one we used in this investigation **urlscan.io** which explains why the verdict on the website was **no classification**. The automated scanner of urlscan.io was not able to get past the captcha thus not being able to see the actual phishing content, this also explains why all images from the history of the scanning only composed of captcha images.

## 6. Payload

- **URL (defanged):** `hxxps://aws-support-cloud[.]com/cp[.]php`
  — credential-harvesting page; 16/91 VirusTotal vendors flagged as Phishing
- **Redirect chain:**
  1. `hxxps://aws-support-cloud[.]com/` → HTTP 302 (observed from urlscan.io)
  2. `hxxps://aws-support-cloud[.]com/cp[.]php` → Page URL (final destination, likely where the harvesting of credential happens.)
  
  Short two-hop chain the root domain immediately redirects to the 
  harvesting endpoint. No intermediary redirectors or URL shorteners used.
- **Attachments:** None - URL-only phishing, no file payload
- **Callback numbers:** None identified
- **urlscan.io:** No classification - consistent with domain being 
  non-resolving (clientHold) at scan time and also possibly due to not getting past the captcha.

## 7. Verdict & Reasoning

**Verdict: Malicious — Credential Harvesting Phishing (High Confidence)**

All indicators point towards  the same conclusion:

- **Domain:** Registered < 48 hours before PhishTank submission this points toward the domain being a 
  throwaway infrastructure. Combosquatting `aws.amazon.com` via 
  `aws-support-cloud[.]com`. Suspended (clientHold) by registrar 
  at time of investigation - consistent with urlscan.io giving `no classification` as a verdict.
- **Hosting:** IP `45.74.61[.]10` on AS-69HOST (AS205397), 8/89 VirusTotal vendors flagged as 
  Phishing/Malicious/Malware; Spamhaus ZEN listed; self-signed TLS 
  certificate; community score on VirusTotal -9.
- **Content:** Through inference from infraastructure the page likely impersonates AWS support portal to harvest credentials 
  via `/cp.php` - a known phishing-kit endpoint pattern attackers use to blend in.
- **No contradictory signals:** Unlike some cases where there are authentication passes 
  but the content is malicious, here every evidence we found such as: domain age, 
  hosting reputation, vendor detections, infrastructure, and content — 
  points to the domain having malicious intent.

## 8. Indicators of Compromise

| Type | Value (defanged) | Context |
|---|---|---|
| Domain | `aws-support-cloud[.]com` | Typosquatting target: aws.amazon.com; registered 2026-09-16; clientHold status |
| IPv4 | `45.74.61[.]10` | Hosting IP — AS-69HOST (AS205397); 8/89 VirusTotal; Spamhaus ZEN listed; self-signed TLS |
| URL | `hxxps://aws-support-cloud[.]com/cp[.]php` | Credential harvesting endpoint |
| Registration date | 2026-09-16 | Domain age < 48 hours at time of detection |
| Registrar abuse contact | abuse@namesilo.com | NameSilo, LLC - report here for takedown (got from WHOIS) |

## 9. MITRE ATT&CK

| ID | Technique | How it applies |
|---|---|---|
| T1598.003 | Phishing for Information: Spearphishing Link | Credential-harvesting page designed to collect user AWS login credentials via a malicious link - primary technique which is based on the evidence (`/cp.php` endpoint, PhishTank classification) |
| T1566.002 | Phishing: Spearphishing Link | Cannot be ruled out - harvested AWS credentials could possibly be used for Initial Access into the cloud environment of the victim. However, the technique depends on the follow-on intent of the the attacker which cannot be observed just from this sample.
| T1036.005 | Masquerading: Match Legitimate Name or Location | Domain combosquats `aws.amazon.com` via `aws-support-cloud[.]com` to appear legitimate |

## 10. Recommended Actions

1. **Block domain and IP at perimeter:** Add `aws-support-cloud[.]com` 
   and `45.74.61[.]10` to the DNS/firewall blocklists
2. **Report to registrar:** Email abuse@namesilo.com. However, through the observable clientHold status
    this may already have been done; confirm and escalate if not
3. **Report to hosting provider:** Report `45.74.61[.]10` / AS-69HOST 
   (AS205397) abuse - check their abuse contact via ARIN/RIPE
4. **Add IOCs to threat-intel feeds:** Domain, IP, and URL to 
   internal blocklists and shared threat-intel platforms
5. **User awareness:** If users may have encountered this link, 
   advise them to change AWS credentials immediately and enable MFA.


