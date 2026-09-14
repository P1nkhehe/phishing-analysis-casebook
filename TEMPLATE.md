<span style="color:#d33">*This entire template is a Claude draft — copy it for each new case and edit freely.*</span>

# Case NN — Short descriptive title

| | |
|---|---|
| **Verdict** | Malicious / Suspicious / Benign |
| **Severity** | Low / Medium / High — one line on why |
| **Type** | Credential harvest / Callback scam / BEC / Malware delivery / Advance-fee fraud |
| **Sample** | `<sha256>.eml` from `<corpus name>` |
| **MITRE ATT&CK** | Txxxx — Technique name |

## 1. Summary

Two or three sentences: what the email claims to be, what it actually is, and the one indicator that decides the verdict.

## 2. Header analysis

### Authentication results

| Check | Result | Notes |
|---|---|---|
| SPF | pass / fail / none / softfail | sender IP vs published SPF record |
| DKIM | pass / fail | `header.d=` domain — does it match `From`? |
| DMARC | pass / fail / none / bestguesspass | is a policy published at all? |
| Composite (compauth) | pass / fail | Microsoft's overall verdict, where present |

### Sender fields

| Field | Value (defanged) |
|---|---|
| From | |
| Reply-To | |
| Return-Path | |
| Sender | |
| Sender IP | |
| Message-ID | |
| Subject | |
| Date | |
| To | (note `undisclosed-recipients` / mass BCC) |

Do `From`, `Reply-To`, and `Return-Path` agree? If not, where do replies actually go?

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
