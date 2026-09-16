# Phishing Analysis Casebook

A hands-on phishing email analysis on real-world samples from a public email corpus from [email-corpus](https://github.com/cw-l/email-corpus). In analyzing each case i made use of the same analyst workflow - header authentication, sender validation, reputation checks, content analysis, IOC extraction, MITRE ATT&CK mapping, and a recommended response all are written up the way a SOC phishing ticket would be.

Samples are analyzed by only the hash and email header only. No attachments are executed and no URL is ever visited directly; all indicators below are defanged.

## Case Index

| # | Case | Type | Verdict | Key indicator | MITRE ATT&CK |
|---|------|------|---------|---------------|--------------|
| 01 | [McAfee renewal - callback scam via Google Calendar](cases/01-mcafee-renewal-callback-scam.md) | Callback phishing (TOAD)</span> | **Malicious** | DKIM fail, SPF none; brand/sender mismatch; phone-number lure | T1566.004 (Phishing: Spearphishing Voice) |
| 02 | [IMF lottery - compromised university account](cases/02-imf-lottery-compromised-account.md) | Advance-fee fraud (419) | **Malicious** |SPF/DKIM pass from a legitimate domain; Reply-To mismatch; contents of email unrelated to sender | T1598, T1586.002 (Phishing for Info: Spearphishing Attachment |

*To be added (Currently Working on): malicious-URL / redirect-chain case · BEC (executive impersonation) case · malicious-attachment case.*

## Methodology

When analyzing each case they need to answer or address the same questions, in order:

1. **Was the email sent from an authorised server?**: SPF, DKIM, DMARC results from `Authentication-Results`; sender IP traced through the `Received` chain and checked against the domain's published SPF and MX records (MXToolbox).
2. **Do the `From`, `Reply-To`, and `Return-Path` agree?**: a mismatch proves replies are routed somewhere other than the apparent sender.
3. **What is the reputation of the sender IP and domain?**: VirusTotal, MXToolbox blacklist check, and where relevant Cisco Talos / AbuseIPDB.
4. **Does the content match the sender?**:brand impersonation, urgency, a financial or credential ask, and whether the sending domain has any legitimate relationship to the claimed organization.
5. **What is the payload?**: links, attachments, or a phone number / callback lure; analyzed via urlscan.io, VirusTotal, or sandbox reports without visiting anything live.
6. **Verdict, IOCs, ATT&CK mapping, and recommended actions.**

## Tools

MXToolbox SuperTool (SPF, DMARC, MX, blacklist) · VirusTotal · Cisco Talos Intelligence · AbuseIPDB · urlscan.io · raw `.eml` header inspection

## Sample source

[https://github.com/cw-l/email-corpus](https://github.com/cw-l/email-corpus)

## Scope & ethics

All samples come from a public research corpus and were analysed in isolation. Recipient details are redacted. Nothing in this repository is executable, and every URL, domain, and IP is defanged (`hxxp://`, `example[.]com`, `1.2.3[.]4`) so it cannot be clicked by accident.
