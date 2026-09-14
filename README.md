# Phishing Analysis Casebook

<span style="color:#d33">Hands-on phishing email analysis on real-world samples from a public email corpus. Each case follows the same analyst workflow — header authentication, sender validation, reputation checks, content analysis, IOC extraction, MITRE ATT&CK mapping, and a recommended response — and is written up the way a SOC phishing ticket would be.</span>

<span style="color:#d33">Samples are analysed by hash and header only. No attachment is ever executed and no URL is ever visited directly; all indicators below are defanged.</span>

## Case Index

| # | Case | Type | Verdict | Key indicator | MITRE ATT&CK |
|---|------|------|---------|---------------|--------------|
| 01 | [McAfee renewal — callback scam via Google Calendar](cases/01-mcafee-renewal-callback-scam.md) | <span style="color:#d33">Callback phishing (TOAD)</span> | <span style="color:#d33">**Malicious**</span> | <span style="color:#d33">DKIM fail, SPF none; brand/sender mismatch; phone-number lure</span> | <span style="color:#d33">T1566.004</span> |
| 02 | [IMF lottery — compromised university account](cases/02-imf-lottery-compromised-account.md) | <span style="color:#d33">Advance-fee fraud (419)</span> | <span style="color:#d33">**Malicious**</span> | <span style="color:#d33">SPF/DKIM pass from a legitimate domain; Reply-To mismatch; content unrelated to sender</span> | <span style="color:#d33">T1598, T1586.002</span> |

<span style="color:#d33">*Planned: malicious-URL / redirect-chain case · BEC (executive impersonation) case · malicious-attachment case.*</span>

## Methodology

<span style="color:#d33">Every case answers the same questions, in order:</span>

1. <span style="color:#d33">**Was the email sent from an authorised server?** — SPF, DKIM, DMARC results from `Authentication-Results`; sender IP traced through the `Received` chain and checked against the domain's published SPF and MX records (MXToolbox).</span>
2. <span style="color:#d33">**Do `From`, `Reply-To`, and `Return-Path` agree?** — a mismatch routes replies somewhere other than the apparent sender.</span>
3. <span style="color:#d33">**What is the reputation of the sender IP and domain?** — VirusTotal, MXToolbox blacklist check, and where relevant Cisco Talos / AbuseIPDB.</span>
4. <span style="color:#d33">**Does the content match the sender?** — brand impersonation, urgency, a financial or credential ask, and whether the sending domain has any legitimate relationship to the claimed organisation.</span>
5. <span style="color:#d33">**What is the payload?** — links, attachments, or a phone number / callback lure; analysed via urlscan.io, VirusTotal, or sandbox reports without visiting anything live.</span>
6. <span style="color:#d33">**Verdict, IOCs, ATT&CK mapping, and recommended actions.**</span>

## Tools

<span style="color:#d33">MXToolbox SuperTool (SPF, DMARC, MX, blacklist) · VirusTotal · Cisco Talos Intelligence · AbuseIPDB · urlscan.io · raw `.eml` header inspection</span>

## Sample source

<span style="color:#d33">[Link to the public email corpus you used — fill in]</span>

## Scope & ethics

<span style="color:#d33">All samples come from a public research corpus and were analysed in isolation. Recipient details are redacted. Nothing in this repository is executable, and every URL, domain, and IP is defanged (`hxxp://`, `example[.]com`, `1.2.3[.]4`) so it cannot be clicked by accident.</span>
