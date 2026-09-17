# Case 02 — IMF / Western Union lottery scam sent from a compromised university account

| | |
|---|---|
| **Verdict** | **Malicious** |
| **Severity** | Low: Commodity advance-fee fraud with no link or attachment; the attackers aim for the recipient to reply with personal and banking details |
| **Type** | Advance-fee fraud (419) sent from a compromised legitimate account |
| **Sample** | `0c82d0952bae458461ceccc56a90d36436a07d871fab89d8cabab71e06acdb79.eml` |
| **MITRE ATT&CK** | T1598 — Phishing for Information · T1586.002 - Compromise Accounts: Email Accounts |

## 1. Summary

A "you have won USD 2.7 million from the IMF" email that passes SPF, DKIM, and composite authentication (compauth) because it sent from a legitimate Thai university domain (`wisut.ac[.]th`) through Google Workspace. The sender account is compromised: the message went to `undisclosed-recipients`, the Reply-To points to an unrelated Gmail address, and the content has nothing to do with the institution sending the email. This is a case where you need more context into a situation as authentication results alone would produce or point you to the wrong answer.

## 2. Header analysis

### Initial findings

Upon opening the email header we are greeted with many things that can aid us in verifying the email.

![ARC and Authentication-Results headers — spf=pass, dkim=pass](../images/case02-01-auth-results.png)

On the authentication results field we can see that the spf analysis returned a pass along with the dkim analysis which means that this email has not been tampered with. So far there are no red flags to note yet, but we will manually check this spf and dkim analysis later as further verification would not hurt.

As we further read the email we find questionable information

![From, Reply-To, Subject, To and Message-ID headers](../images/case02-02-from-replyto.png)

The Reply-To and the From field as different which sometimes doesn't automatically disqualify an email from being illegitimate. However, in this case the email addresses are what's really questionable here, these are not legitimate email addresses or known ones. We will further explore this on the mxsupertool. Additionally, we also observe in `To: undisclosed-recipients:;` that the email was mass-mail via the use of BCC. If we were to compare this with legitimate emails wherein a personal notification is addressed to a named recipient; a hidden bulk recipient list such as this one is a strong indicator of a spoofed email. If we observe the `Message-ID` we can see it starts with `CAMhPCoEJ…@mail.gmail.com` the `CA…@mail.gmail.com` pattern specifically means that the email/message itself was composed directly in Gmail as opposed to someone just using a bulk email service provider, which is consistent with someone currently logged into the compromised account and actively using it.


### Authentication results

| Check | Result | Notes |
|---|---|---|
| SPF | **pass** | sender IP `209.85.210[.]67` is within Google's SPF, which `wisut.ac[.]th` includes |
| DKIM | **pass** | `header.d=wisut-ac-th.20230601.gappssmtp.com` - signed by the domain's Google Workspace tenant |
| DMARC | **bestguesspass** | no DMARC record published; inferred, not enforced |
| ARC | pass | chain sealed by microsoft.com, i=2 |
| Composite (compauth) | **pass**, reason=109 | authentication is genuine - the account, not the headers, is the problem |

### Sender fields

| Field | Value (defanged) |
|---|---|
| From | Mrs Cecilia Ralph `<29764@wisut.ac[.]th>` |
| Reply-To | `fdy3215@gmail[.]com` — **does not match From** |
| To | `undisclosed-recipients:;` (mass BCC) |
| Sender IP | `209.85.210[.]67` (Google outbound) |
| Message-ID | `<CAMhPCoEJ+bLD8wRLYR1Wjx9SMP1=J-iB-oyZk88MA5nyfcuLgQ@mail.gmail.com>` |
| Subject | Congratulations to you |
| Date | Wed, 4 Mar 2026 09:58:03 +0300 |

## 3. Content analysis

Contents of the Email.

![Email body — IMF / Western Union compensation lure, part 1](../images/case02-03-email-body-1.png)

![Email body — IMF / Western Union compensation lure, part 2](../images/case02-04-email-body-2.png)

Alright, upon reading the contents of the email we can deduce that is an email telling someone that they have won something as their email was luckily chosen for the jackpot prize yearly. And then proceeds to ask for their personal information. In this case the lure is the 2.7 million USD "compensation fund" supposedly from the IMF, to be paid 10,000 USD instalments after they send their "complete information" so a "Mr. Jerry Campbell". That's it, no link, no attachments the payload here is the reply itself which is a class advance-fee fraud wherein the personal data is harvested first, then a "processing fee" which in this case is the "activation fee"


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
| `wisut.ac[.]th` | legitimate | real educational institution on Google Workspace; the domain itself is not malicious — one of its accounts is |
| `209.85.210[.]67` | listed on 0SPAM (1 of 60) | Google shared outbound pool, same caveat as Case 01 — not attributable to this sender |
| `fdy3215@gmail[.]com` | — | Reply-To; throwaway address controlled by the fraudster |

## 5. Payload

**Links:** none
**Attachments:** none
**Ask:** reply with full personal details to the Reply-To address / "Mr. Jerry Campbell"

## 6. Verdict & reasoning

This email is somewhat difficult to assess as there are a mix of green flags aswell as redflags which include the ip of the sender being listed within the spf list of google.com while also being found on the blacklist. But if we were to take one thing from this entire email if would be that the contents are not associated with the sender of the email or even the email they plugged in the contents to contact them. The email tells them its from the IMF and to contact the IMF but upon observation the contact email, reply to, and from field are all not associated with the IMF. The sender of the email itself is from a school, a school would not send an email with contents regarding winning a million-dollar prize. My conclusion for this is that the email is from a compromised account, this explains why it passed the dkim and spf test properly thus giving a combination of green and red flags. Further supporting this claim we observed the `undisclosed-recipients` mass-mailing and the Gmail-web Message-ID pointing towards the highly likely possibility that someone logged into a real account and blasted a scam.  This shows us how important context, research, and analytical skills are when it comes to looking at emails as they might seem legitimate and come from a reputable email or domain.


## 7. Indicators of Compromise

| Type | Value (defanged) | Context |
|---|---|---|
| Email | `29764@wisut.ac[.]th` | From - compromised legitimate account |
| Email | `fdy3215@gmail[.]com` | Reply-To - attacker-controlled |
| IPv4 | `209.85.210[.]67` | sender IP - Google shared outbound, low confidence as a standalone IOC |
| Message-ID | `<CAMhPCoEJ+bLD8wRLYR1Wjx9SMP1=J-iB-oyZk88MA5nyfcuLgQ@mail.gmail.com>` | exact-match purge key |
| String | "Mr. Jerry Campbell", "Administrator's Trust Fund" | lure text - useful for content-based mailbox search |
| File hash | `0c82d0952bae458461ceccc56a90d36436a07d871fab89d8cabab71e06acdb79` | .eml sample (SHA-256) |

## 8. MITRE ATT&CK

| ID | Technique | How it applies |
|---|---|---|
| T1598 | Phishing for Information | the goal is to harvest personal and banking details via reply, not to deliver a payload |
| T1586.002 | Compromise Accounts: Email Accounts | sent from a genuine university Workspace account under attacker control, inheriting its SPF/DKIM reputation |

## 9. Recommended actions

1. Block `fdy3215@gmail[.]com` (the Reply-To) at the gateway - this is the address the fraud actually depends on.
2. Block `29764@wisut.ac[.]th` as a sender **temporarily**; do not block the whole `wisut.ac[.]th` domain, which is a legitimate institution.
3. Search all mailboxes for the Message-ID and the subject "Congratulations to you" and purge.
4. Notify the institution's abuse / IT contact that account `29764` is compromised, so they can reset it — this is the action that addresses the source of the compromise.
5. Do **not** block `209.85.210[.]67` — Google shared outbound infrastructure.
6. If any user replied: treat their submitted personal data as exposed and follow the identity-theft response process.
