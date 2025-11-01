# Phishing Email Analysis Template

Use this template to manually analyze suspicious emails.

---

## Email Information

**Date Received:** _________________

**Subject:** _________________

**From (Display Name):** _________________

**From (Email Address):** _________________

**To:** _________________

**Date Sent:** _________________

---

## 1. Sender Analysis

### Email Address Examination

**Sender Domain:** _________________

**Is domain legitimate?** ☐ Yes ☐ No ☐ Uncertain

**Red Flags Found:**
- ☐ Numbers in domain (e.g., paypa1.com)
- ☐ Misspelled domain
- ☐ Free email service (Gmail, Yahoo) for business
- ☐ Suspicious keywords (verify, secure, account)
- ☐ Reply-To address different from From
- ☐ Display name doesn't match email domain

**Notes:**
_________________________________________________________________________________

---

## 2. Header Analysis

### Authentication Results

**SPF:** ☐ Pass ☐ Fail ☐ None

**DKIM:** ☐ Pass ☐ Fail ☐ None

**DMARC:** ☐ Pass ☐ Fail ☐ None

### Received Headers

**Number of hops:** _________________

**Originating IP:** _________________

**Originating Country:** _________________

**Red Flags Found:**
- ☐ Authentication failures
- ☐ Suspicious origin country (.ru, .cn, etc.)
- ☐ IP doesn't match claimed sender
- ☐ Unusual routing path

**Notes:**
_________________________________________________________________________________

---

## 3. Link Analysis

### URLs Found

**URL 1:** _________________

**URL 2:** _________________

**URL 3:** _________________

**Red Flags Found:**
- ☐ HTTP instead of HTTPS
- ☐ IP address in URL
- ☐ URL shorteners (bit.ly, tinyurl)
- ☐ Typosquatting (similar to legitimate domain)
- ☐ Suspicious TLD (.ru, .tk, .xyz)
- ☐ Mismatched display text vs actual URL

**Notes:**
_________________________________________________________________________________

---

## 4. Content Analysis

### Subject Line

**Contains urgent language?** ☐ Yes ☐ No

**Threatening or alarming?** ☐ Yes ☐ No

### Email Body

**Greeting Type:**
- ☐ Personalized (uses your name)
- ☐ Generic ("Dear Customer")
- ☐ No greeting

**Red Flags Found:**
- ☐ Urgent/threatening language
- ☐ Requests for sensitive information (password, SSN, credit card)
- ☐ Spelling or grammar errors
- ☐ Generic greeting
- ☐ Threats of account closure/suspension
- ☐ Too good to be true offers
- ☐ Requests to bypass normal procedures

**Urgent phrases found:**
_________________________________________________________________________________

**Spelling/grammar errors:**
_________________________________________________________________________________

---

## 5. Attachment Analysis

**Number of attachments:** _________________

**Attachment 1:**
- Filename: _________________
- Type: _________________
- Red flags: ☐ .exe/.scr/.bat ☐ Double extension ☐ Macro-enabled Office doc

**Attachment 2:**
- Filename: _________________
- Type: _________________
- Red flags: ☐ .exe/.scr/.bat ☐ Double extension ☐ Macro-enabled Office doc

---

## 6. Social Engineering Tactics

**Tactics Used:**
- ☐ Fear/Threat
- ☐ Urgency
- ☐ Authority (impersonating boss/company)
- ☐ Curiosity
- ☐ Greed/Reward
- ☐ Helpfulness
- ☐ Familiarity

**Explanation:**
_________________________________________________________________________________

---

## 7. Risk Assessment

### Indicators Summary

**Total Red Flags Found:** _________________

**Severity of Indicators:**
- ☐ Critical (authentication failures, malicious links)
- ☐ High (suspicious domain, urgent threats)
- ☐ Medium (generic greeting, minor errors)
- ☐ Low (minor inconsistencies)

### Overall Assessment

**Risk Level:**
- ☐ CRITICAL - Definitely phishing
- ☐ HIGH - Likely phishing
- ☐ MEDIUM - Suspicious, needs verification
- ☐ LOW - Appears legitimate

**Confidence Level:** _________________

---

## 8. Verdict

**Is this email phishing?** ☐ Yes ☐ No ☐ Uncertain

**Primary reasons:**
1. _________________________________________________________________________________
2. _________________________________________________________________________________
3. _________________________________________________________________________________

---

## 9. Recommendations

**Actions to take:**
- ☐ Delete immediately
- ☐ Report to IT/security team
- ☐ Report to email provider
- ☐ Report to impersonated company
- ☐ Verify through independent channel
- ☐ If interacted: change passwords, scan for malware
- ☐ If provided info: contact bank, monitor accounts

**Specific recommendations:**
_________________________________________________________________________________
_________________________________________________________________________________

---

## 10. Lessons Learned

**What made this email suspicious?**
_________________________________________________________________________________

**What could trick users?**
_________________________________________________________________________________

**How to identify similar attacks?**
_________________________________________________________________________________

---

## Additional Notes

_________________________________________________________________________________
_________________________________________________________________________________
_________________________________________________________________________________

---

**Analyst Name:** _________________

**Analysis Date:** _________________

**Time Spent:** _________________

---

## Supporting Evidence

Attach:
- ☐ Screenshots of email
- ☐ Full email headers
- ☐ URL scan results
- ☐ VirusTotal results (if applicable)
- ☐ Other relevant evidence

---

**Template Version 1.0**
