# Case 02 — IMF / Western Union lottery scam sent from a compromised university account

| | |
|---|---|
| **Verdict** | <span style="color:#d33">**Malicious**</span> |
| **Severity** | <span style="color:#d33">Low — commodity advance-fee fraud with no link or attachment; the risk is a recipient replying with personal and banking details</span> |
| **Type** | <span style="color:#d33">Advance-fee fraud (419) sent from a compromised legitimate account</span> |
| **Sample** | `0c82d0952bae458461ceccc56a90d36436a07d871fab89d8cabab71e06acdb79.eml` |
| **MITRE ATT&CK** | <span style="color:#d33">T1598 — Phishing for Information · T1586.002 — Compromise Accounts: Email Accounts</span> |

## 1. Summary

<span style="color:#d33">A "you have won USD 2.7 million from the IMF" email that passes SPF, DKIM, and composite authentication because it was genuinely sent from a real Thai university domain (`wisut.ac[.]th`) through Google Workspace. The sender account is compromised: the message went to `undisclosed-recipients`, the Reply-To points to an unrelated Gmail address, and the content has nothing to do with the sending institution. This is the case where authentication results alone would produce the wrong answer.</span>

## 2. Header analysis

### Initial findings

Upon opening the email header we are greeted with many things that can aid us in verifying the email.

![ARC and Authentication-Results headers — spf=pass, dkim=pass](../images/case02-01-auth-results.png)

On the authentication results field we can see that the spf analysis returned a pass along with the dkim analysis which means that this email has not been tampered with. So far there are no red flags to note yet, but we will manually check this spf and dkim analysis later as further verification would not hurt.

As we further read the email we find questionable information

![From, Reply-To, Subject, To and Message-ID headers](../images/case02-02-from-replyto.png)

The Reply-To and the From field as different which sometimes doesn't automatically disqualify an email from being illegitimate. However, in this case the email addresses are what's really questionable here, these are not legitimate email addresses or known ones. We will further explore this on the mxsupertool.

> <span style="color:#d33">**Added observations from the same screenshot:**</span>
> - <span style="color:#d33">`To: undisclosed-recipients:;` — the message was mass-mailed via BCC. A legitimate personal notification is addressed to a named recipient; a hidden bulk recipient list is a strong scam indicator on its own.</span>
> - <span style="color:#d33">The `Message-ID` begins with `CAMhPCoEJ…@mail.gmail.com` — the `CA…@mail.gmail.com` pattern means it was composed in the Gmail web interface, consistent with someone logged into the compromised Workspace account rather than a bulk-mailing tool.</span>
> - <span style="color:#d33">`dmarc=bestguesspass` is not a real DMARC pass. It means `wisut.ac[.]th` publishes **no DMARC record** and Microsoft inferred a pass from SPF/DKIM alignment. The domain has no DMARC policy that could have blocked abuse of its own accounts.</span>

### Authentication results

<span style="color:#d33">*(table added — values read directly from the header screenshot above)*</span>

| Check | Result | Notes |
|---|---|---|
| <span style="color:#d33">SPF</span> | <span style="color:#d33">**pass**</span> | <span style="color:#d33">sender IP `209.85.210[.]67` is within Google's SPF, which `wisut.ac[.]th` includes</span> |
| <span style="color:#d33">DKIM</span> | <span style="color:#d33">**pass**</span> | <span style="color:#d33">`header.d=wisut-ac-th.20230601.gappssmtp.com` — signed by the domain's Google Workspace tenant</span> |
| <span style="color:#d33">DMARC</span> | <span style="color:#d33">**bestguesspass**</span> | <span style="color:#d33">no DMARC record published; inferred, not enforced</span> |
| <span style="color:#d33">ARC</span> | <span style="color:#d33">pass</span> | <span style="color:#d33">chain sealed by microsoft.com, i=2</span> |
| <span style="color:#d33">Composite (compauth)</span> | <span style="color:#d33">**pass**, reason=109</span> | <span style="color:#d33">authentication is genuine — the account, not the headers, is the problem</span> |

### Sender fields

| Field | Value (defanged) |
|---|---|
| <span style="color:#d33">From</span> | <span style="color:#d33">Mrs Cecilia Ralph `<29764@wisut.ac[.]th>`</span> |
| <span style="color:#d33">Reply-To</span> | <span style="color:#d33">`fdy3215@gmail[.]com` — **does not match From**</span> |
| <span style="color:#d33">To</span> | <span style="color:#d33">`undisclosed-recipients:;` (mass BCC)</span> |
| <span style="color:#d33">Sender IP</span> | <span style="color:#d33">`209.85.210[.]67` (Google outbound)</span> |
| <span style="color:#d33">Message-ID</span> | <span style="color:#d33">`<CAMhPCoEJ+bLD8wRLYR1Wjx9SMP1=J-iB-oyZk88MA5nyfcuLgQ@mail.gmail.com>`</span> |
| <span style="color:#d33">Subject</span> | <span style="color:#d33">Congratulations to you</span> |
| <span style="color:#d33">Date</span> | <span style="color:#d33">Wed, 4 Mar 2026 09:58:03 +0300</span> |

## 3. Content analysis

Contents of the Email.

![Email body — IMF / Western Union compensation lure, part 1](../images/case02-03-email-body-1.png)

![Email body — IMF / Western Union compensation lure, part 2](../images/case02-04-email-body-2.png)

Alright, upon reading the contents of the email we can deduce that is an email telling someone that they have won something as their email was luckily chosen for the jackpot prize yearly. And then proceeds to ask for their personal information.

> <span style="color:#d33">**Added detail:** the lure is a USD 2.7 million "compensation fund" from the IMF, to be paid via Western Union in USD 10,000 instalments once the recipient sends their "complete information" to a "Mr. Jerry Campbell." No link, no attachment — the payload is the reply itself. This is classic advance-fee fraud: the personal data is harvested first, then a "processing fee" is requested before any payment.</span>

## 4. Sender validation & reputation

Now proceeding to the mxsupertool analysis for the spf and dmarc.

![MXToolbox SPF lookup for wisut.ac.th — includes Google's SPF](../images/case02-05-mxtoolbox-spf.png)

So far so good the ip of the sender matches what we saw from the mxsupertool as the domain wisut.ac.th includes the spf of google.com which contains the ip of the sender.

Lets now check the IP of the sender

![MXToolbox blacklist check for 209.85.210.67](../images/case02-06-sender-ip-blacklist.png)

Upon checking the ip of the sender once again it gave us that its listed in the blacklist.

Looking up the domain:

![wisut.ac.th — legitimate school website](../images/case02-07-domain-lookup.png)

Upon searching the domain we can see that it's a legitimate site and a legitimate school, this now explains why the spf and dkim passed because it's a legitimate domain rather than something an attacker just created on the spot. This also explains why they included google.com in their spf list because they use google workspace within the institution.

| Indicator | Reputation | Notes |
|---|---|---|
| <span style="color:#d33">`wisut.ac[.]th`</span> | <span style="color:#d33">legitimate</span> | <span style="color:#d33">real educational institution on Google Workspace; the domain itself is not malicious — one of its accounts is</span> |
| <span style="color:#d33">`209.85.210[.]67`</span> | <span style="color:#d33">listed on 0SPAM (1 of 60)</span> | <span style="color:#d33">Google shared outbound pool, same caveat as Case 01 — not attributable to this sender</span> |
| <span style="color:#d33">`fdy3215@gmail[.]com`</span> | <span style="color:#d33">—</span> | <span style="color:#d33">Reply-To; throwaway address controlled by the fraudster</span> |

## 5. Payload

- <span style="color:#d33">**Links:** none</span>
- <span style="color:#d33">**Attachments:** none</span>
- <span style="color:#d33">**Ask:** reply with full personal details to the Reply-To address / "Mr. Jerry Campbell"</span>

## 6. Verdict & reasoning

This email is somewhat difficult to assess as there are a mix of green flags aswell as redflags which include the ip of the sender being listed within the spf list of google.com while also being found on the blacklist. But if we were to take one thing from this entire email if would be that the contents are not associated with the sender of the email or even the email they plugged in the contents to contact them. The email tells them its from the IMF and to contact the IMF but upon observation the contact email, reply to, and from field are all not associated with the IMF. The sender of the email itself is from a school, a school would not send an email with contents regarding winning a million-dollar prize. My conclusion for this is that the email is from a compromised account, this explains why it passed the dkim and spf test properly thus giving a combination of green and red flags. This shows us how important context, research, and analytical skills are when it comes to looking at emails as they might seem legitimate and come from a reputable email or domain.

> <span style="color:#d33">**Editorial note:** the reasoning above is the strongest part of this casebook — reaching *compromised account* from a message that passes every authentication check is exactly the judgement call that separates analysis from checklist-following. Two supporting points worth adding to the verdict: the `undisclosed-recipients` mass-mailing and the Gmail-web Message-ID both corroborate "someone logged into a real account and blasted a scam," rather than spoofing.</span>

## 7. Indicators of Compromise

| Type | Value (defanged) | Context |
|---|---|---|
| <span style="color:#d33">Email</span> | <span style="color:#d33">`29764@wisut.ac[.]th`</span> | <span style="color:#d33">From — compromised legitimate account</span> |
| <span style="color:#d33">Email</span> | <span style="color:#d33">`fdy3215@gmail[.]com`</span> | <span style="color:#d33">Reply-To — attacker-controlled</span> |
| <span style="color:#d33">IPv4</span> | <span style="color:#d33">`209.85.210[.]67`</span> | <span style="color:#d33">sender IP — Google shared outbound, low confidence as a standalone IOC</span> |
| <span style="color:#d33">Message-ID</span> | <span style="color:#d33">`<CAMhPCoEJ+bLD8wRLYR1Wjx9SMP1=J-iB-oyZk88MA5nyfcuLgQ@mail.gmail.com>`</span> | <span style="color:#d33">exact-match purge key</span> |
| <span style="color:#d33">String</span> | <span style="color:#d33">"Mr. Jerry Campbell", "Administrator's Trust Fund"</span> | <span style="color:#d33">lure text — useful for content-based mailbox search</span> |
| <span style="color:#d33">File hash</span> | <span style="color:#d33">`0c82d0952bae458461ceccc56a90d36436a07d871fab89d8cabab71e06acdb79`</span> | <span style="color:#d33">.eml sample (SHA-256)</span> |

## 8. MITRE ATT&CK

| ID | Technique | How it applies |
|---|---|---|
| <span style="color:#d33">T1598</span> | <span style="color:#d33">Phishing for Information</span> | <span style="color:#d33">the goal is to harvest personal and banking details via reply, not to deliver a payload</span> |
| <span style="color:#d33">T1586.002</span> | <span style="color:#d33">Compromise Accounts: Email Accounts</span> | <span style="color:#d33">sent from a genuine university Workspace account under attacker control, inheriting its SPF/DKIM reputation</span> |

## 9. Recommended actions

1. <span style="color:#d33">Block `fdy3215@gmail[.]com` (the Reply-To) at the gateway — this is the address the fraud actually depends on.</span>
2. <span style="color:#d33">Block `29764@wisut.ac[.]th` as a sender **temporarily**; do not block the whole `wisut.ac[.]th` domain, which is a legitimate institution.</span>
3. <span style="color:#d33">Search all mailboxes for the Message-ID and the subject "Congratulations to you" and purge.</span>
4. <span style="color:#d33">Notify the institution's abuse / IT contact that account `29764` is compromised, so they can reset it — this is the only action that stops the source.</span>
5. <span style="color:#d33">Do **not** block `209.85.210[.]67` — Google shared outbound infrastructure.</span>
6. <span style="color:#d33">If any user replied: treat their submitted personal data as exposed and follow the identity-theft response process.</span>
