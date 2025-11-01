# Cyber-security---Task-2

## Overview

This project demonstrates phishing email analysis techniques to identify and understand email-based threats. It's an educational tool to learn about phishing tactics and email security.

**⚠️ IMPORTANT:** This is for educational purposes only. Never interact with real phishing emails unless in a controlled environment.

## Objective

Identify phishing characteristics in suspicious email samples and understand common attack vectors.

## Tools Used

- **Python 3** - Email header analysis automation
- **Online Header Analyzers** - MXToolbox, Google Admin Toolbox
- **Text Editors** - To examine email source code

## What's Included

- Sample phishing emails (`.eml` format)
- Python script for automated analysis
- Detailed phishing analysis reports
- Interview questions with answers

## Quick Start

### Analyze Sample Emails

```bash
# Run the analysis script
python3 email_analyzer.py samples/phishing_sample_1.eml

# Or analyze all samples
python3 email_analyzer.py samples/*.eml
```

### Manual Analysis Steps

1. **Examine the sender's email address**
2. **Check email headers** for discrepancies
3. **Identify suspicious links** or attachments
4. **Look for urgent language** or threats
5. **Check for spelling/grammar errors**
6. **Verify mismatched URLs**

## Phishing Indicators Checklist

✅ **Sender Address:**
- Mismatched or spoofed domain
- Random characters or numbers
- Free email service (Gmail, Yahoo) for business

✅ **Email Headers:**
- Originating IP doesn't match claimed sender
- Multiple "Received" hops through suspicious servers
- SPF/DKIM/DMARC failures

✅ **Email Body:**
- Urgent or threatening language
- Requests for personal/financial information
- Spelling and grammar errors
- Generic greetings ("Dear Customer")

✅ **Links and URLs:**
- Mismatched display text vs. actual URL
- Shortened URLs (bit.ly, tinyurl)
- Suspicious domains (typosquatting)
- Non-HTTPS for sensitive actions

✅ **Attachments:**
- Unexpected attachments
- Executable files (.exe, .scr, .bat)
- Office docs with macros
- Compressed files (.zip, .rar)

## Common Phishing Types

1. **Spear Phishing** - Targeted attacks on specific individuals
2. **Whaling** - Attacks targeting executives
3. **Clone Phishing** - Legitimate email replicated with malicious content
4. **Business Email Compromise (BEC)** - Impersonating company executives
5. **Vishing** - Voice phishing via phone calls
6. **Smishing** - SMS/text message phishing

## Red Flags Examples

**Suspicious Sender:**
```
Display: "PayPal Security"
Actual: security-paypal@gmail.com ❌
```

**Mismatched URL:**
```
Display text: "Click here to verify your account"
Actual link: http://paypa1.suspicious-site.ru ❌
```

**Urgent Language:**
```
"Your account will be suspended in 24 hours!"
"Immediate action required!"
"Unusual activity detected - verify now!"
```

## Online Tools for Analysis

- **MXToolbox Header Analyzer**: https://mxtoolbox.com/EmailHeaders.aspx
- **Google Admin Toolbox**: https://toolbox.googleapps.com/apps/messageheader/
- **VirusTotal**: https://www.virustotal.com (for attachments)
- **URLScan.io**: https://urlscan.io/ (for suspicious URLs)

## Files Included

- `email_analyzer.py` - Python script for automated analysis
- `samples/` - Sample phishing emails
- `reports/` - Analysis reports
- `INTERVIEW_QUESTIONS.md` - Detailed Q&A
- `ANALYSIS_TEMPLATE.md` - Report template

## Best Practices

**If you receive a suspected phishing email:**

1. **Don't click** any links or download attachments
2. **Don't reply** to the email
3. **Don't provide** personal information
4. **Report** to your IT/security team
5. **Delete** the email after reporting
6. **Verify** by contacting the organization directly

## Key Learnings

- How to identify phishing emails
- Email header analysis techniques
- Common social engineering tactics
- Proper response to phishing attempts

## Ethical Use

This project is for **educational purposes only**:
- Use only sample/simulated phishing emails
- Never create or send real phishing emails
- Respect privacy and security laws
- Report real phishing to proper authorities

---

**Stay safe online!** 🛡️
