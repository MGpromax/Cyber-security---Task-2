#!/usr/bin/env python3
"""
Phishing Email Analyzer
Educational tool for analyzing suspicious emails and identifying phishing indicators
"""

import email
import re
import sys
from email import policy
from email.parser import BytesParser
from datetime import datetime
import os


class PhishingAnalyzer:
    """Analyzes emails for phishing indicators"""

    def __init__(self, email_file):
        self.email_file = email_file
        self.msg = None
        self.indicators = []
        self.risk_score = 0

    def load_email(self):
        """Load and parse the email file"""
        try:
            with open(self.email_file, 'rb') as f:
                self.msg = BytesParser(policy=policy.default).parse(f)
            return True
        except Exception as e:
            print(f"[!] Error loading email: {e}")
            return False

    def analyze_sender(self):
        """Analyze sender email address for spoofing"""
        print("\n" + "=" * 70)
        print("1. SENDER ANALYSIS")
        print("=" * 70)

        from_header = self.msg.get('From', '')
        reply_to = self.msg.get('Reply-To', '')

        print(f"From: {from_header}")
        if reply_to:
            print(f"Reply-To: {reply_to}")

        # Extract email address
        email_match = re.search(r'<(.+?)>', from_header)
        sender_email = email_match.group(1) if email_match else from_header

        print(f"\nExtracted Sender Email: {sender_email}")

        # Check for common phishing patterns
        red_flags = []

        # Check for number substitutions (e.g., paypa1.com instead of paypal.com)
        if re.search(r'[0-9]', sender_email.split('@')[1] if '@' in sender_email else ''):
            red_flags.append("⚠️  Domain contains numbers (possible typosquatting)")
            self.risk_score += 2

        # Check for free email services for business purposes
        free_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'mail.com']
        domain = sender_email.split('@')[1] if '@' in sender_email else ''
        if any(free in domain for free in free_domains):
            if 'security' in from_header.lower() or 'admin' in from_header.lower():
                red_flags.append("⚠️  Business/Security email using free email service")
                self.risk_score += 3

        # Check for suspicious keywords in domain
        suspicious_keywords = ['verify', 'secure', 'account', 'update', 'confirm', 'login']
        if any(keyword in domain.lower() for keyword in suspicious_keywords):
            red_flags.append("⚠️  Suspicious keywords in domain name")
            self.risk_score += 2

        # Check Reply-To mismatch
        if reply_to and reply_to != from_header:
            red_flags.append("⚠️  Reply-To address differs from From address")
            self.risk_score += 2

        # Check for display name mismatch
        if '<' in from_header:
            display_name = from_header.split('<')[0].strip().strip('"')
            if display_name and sender_email:
                # Check if display name mentions one company but email is different
                companies = ['paypal', 'microsoft', 'amazon', 'apple', 'google', 'facebook']
                for company in companies:
                    if company in display_name.lower() and company not in sender_email.lower():
                        red_flags.append(f"⚠️  Display name mentions '{company}' but email domain doesn't match")
                        self.risk_score += 3

        if red_flags:
            print("\n🚨 SENDER RED FLAGS FOUND:")
            for flag in red_flags:
                print(f"  {flag}")
            self.indicators.extend(red_flags)
        else:
            print("\n✅ No obvious sender red flags detected")

    def analyze_headers(self):
        """Analyze email headers for discrepancies"""
        print("\n" + "=" * 70)
        print("2. HEADER ANALYSIS")
        print("=" * 70)

        # Check SPF, DKIM, DMARC
        auth_results = self.msg.get('Authentication-Results', '')
        received_spf = self.msg.get('Received-SPF', '')

        print("\nAuthentication Results:")
        if auth_results:
            print(auth_results)
        if received_spf:
            print(f"SPF: {received_spf}")

        red_flags = []

        # Check for failed authentication
        if 'spf=fail' in auth_results.lower() or 'fail' in received_spf.lower():
            red_flags.append("⚠️  SPF authentication FAILED")
            self.risk_score += 3

        if 'dkim=fail' in auth_results.lower():
            red_flags.append("⚠️  DKIM authentication FAILED")
            self.risk_score += 3

        if 'dmarc=fail' in auth_results.lower():
            red_flags.append("⚠️  DMARC authentication FAILED")
            self.risk_score += 3

        # Analyze Received headers
        received_headers = self.msg.get_all('Received', [])
        print(f"\nNumber of 'Received' hops: {len(received_headers)}")

        if received_headers:
            print("\nFirst Received Header (origin):")
            print(received_headers[-1][:200] + "..." if len(received_headers[-1]) > 200 else received_headers[-1])

            # Check for suspicious IPs or domains
            for received in received_headers:
                # Look for suspicious countries or IPs
                if re.search(r'\.(ru|cn|tk|ml|ga)\b', received, re.IGNORECASE):
                    red_flags.append("⚠️  Email routed through suspicious domain (.ru, .cn, .tk, etc.)")
                    self.risk_score += 2
                    break

        if red_flags:
            print("\n🚨 HEADER RED FLAGS FOUND:")
            for flag in red_flags:
                print(f"  {flag}")
            self.indicators.extend(red_flags)
        else:
            print("\n✅ Headers appear normal (or authentication not available)")

    def analyze_links(self):
        """Analyze links and URLs in the email"""
        print("\n" + "=" * 70)
        print("3. LINK ANALYSIS")
        print("=" * 70)

        # Get email body
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == "text/html":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
                elif part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
        else:
            body = self.msg.get_payload(decode=True).decode('utf-8', errors='ignore')

        # Find all URLs
        url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
        urls = re.findall(url_pattern, body)

        # Also find HTML hrefs
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, body)

        all_urls = list(set(urls + hrefs))

        print(f"\nFound {len(all_urls)} unique URL(s)")

        red_flags = []

        for url in all_urls:
            print(f"\nURL: {url}")

            # Check for HTTP instead of HTTPS
            if url.startswith('http://'):
                red_flags.append(f"⚠️  Non-HTTPS URL: {url}")
                self.risk_score += 1

            # Check for IP addresses in URL
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                red_flags.append(f"⚠️  URL uses IP address instead of domain: {url}")
                self.risk_score += 2

            # Check for URL shorteners
            shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'short.link']
            if any(short in url.lower() for short in shorteners):
                red_flags.append(f"⚠️  URL shortener detected: {url}")
                self.risk_score += 2

            # Check for typosquatting
            legitimate_domains = {
                'paypal.com': ['paypa1', 'paypai', 'paypa11', 'paypaal'],
                'microsoft.com': ['micros0ft', 'rnicrosoft', 'micosoft'],
                'amazon.com': ['amaz0n', 'arnazon', 'amazom'],
                'apple.com': ['app1e', 'appl3', 'appie'],
                'google.com': ['g00gle', 'googie', 'gooogle']
            }

            for legit, typos in legitimate_domains.items():
                for typo in typos:
                    if typo in url.lower():
                        red_flags.append(f"⚠️  Possible typosquatting: {url} (similar to {legit})")
                        self.risk_score += 3

            # Check for suspicious TLDs
            suspicious_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.online', '.xyz']
            if any(url.lower().endswith(tld) for tld in suspicious_tlds):
                red_flags.append(f"⚠️  Suspicious top-level domain: {url}")
                self.risk_score += 2

        if red_flags:
            print("\n🚨 LINK RED FLAGS FOUND:")
            for flag in red_flags:
                print(f"  {flag}")
            self.indicators.extend(red_flags)
        else:
            print("\n✅ No suspicious links detected")

    def analyze_content(self):
        """Analyze email content for phishing indicators"""
        print("\n" + "=" * 70)
        print("4. CONTENT ANALYSIS")
        print("=" * 70)

        subject = self.msg.get('Subject', '')
        print(f"\nSubject: {subject}")

        # Get email body
        body = ""
        if self.msg.is_multipart():
            for part in self.msg.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    break
                elif part.get_content_type() == "text/html":
                    # Strip HTML for text analysis
                    html_body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    body = re.sub('<[^<]+?>', '', html_body)
        else:
            body = self.msg.get_payload(decode=True).decode('utf-8', errors='ignore')

        red_flags = []

        # Check for urgent language
        urgent_phrases = [
            'urgent', 'immediate action', 'act now', 'within 24 hours',
            'suspended', 'expires today', 'expire', 'limited time',
            'verify now', 'confirm now', 'update now', 'click here immediately'
        ]

        found_urgent = [phrase for phrase in urgent_phrases if phrase in body.lower() or phrase in subject.lower()]
        if found_urgent:
            red_flags.append(f"⚠️  Urgent/threatening language detected: {', '.join(found_urgent[:3])}")
            self.risk_score += 2

        # Check for generic greetings
        generic_greetings = ['dear customer', 'dear user', 'dear valued', 'hello,', 'dear member']
        if any(greeting in body.lower() for greeting in generic_greetings):
            red_flags.append("⚠️  Generic greeting (no personalization)")
            self.risk_score += 1

        # Check for requests for sensitive information
        sensitive_requests = [
            'social security', 'ssn', 'credit card', 'password',
            'pin', 'account number', 'date of birth', 'mother maiden name'
        ]
        found_sensitive = [req for req in sensitive_requests if req in body.lower()]
        if found_sensitive:
            red_flags.append(f"⚠️  Requests sensitive information: {', '.join(found_sensitive)}")
            self.risk_score += 3

        # Check for spelling errors (common indicator)
        misspellings = [
            ('loose', 'lose'), ('loosing', 'losing'), ('immediatly', 'immediately'),
            ('recieve', 'receive'), ('seperate', 'separate')
        ]
        found_errors = []
        for wrong, correct in misspellings:
            if wrong in body.lower():
                found_errors.append(f"{wrong} (should be '{correct}')")

        if found_errors:
            red_flags.append(f"⚠️  Spelling errors found: {', '.join(found_errors)}")
            self.risk_score += 2

        # Check for threats
        threats = ['account will be closed', 'account will be suspended', 'legal action',
                   'will be charged', 'have been charged']
        found_threats = [threat for threat in threats if threat in body.lower()]
        if found_threats:
            red_flags.append(f"⚠️  Contains threats: {', '.join(found_threats[:2])}")
            self.risk_score += 2

        if red_flags:
            print("\n🚨 CONTENT RED FLAGS FOUND:")
            for flag in red_flags:
                print(f"  {flag}")
            self.indicators.extend(red_flags)
        else:
            print("\n✅ Content appears normal")

    def analyze_attachments(self):
        """Analyze attachments for suspicious files"""
        print("\n" + "=" * 70)
        print("5. ATTACHMENT ANALYSIS")
        print("=" * 70)

        attachments = []
        for part in self.msg.walk():
            if part.get_content_disposition() == 'attachment':
                filename = part.get_filename()
                attachments.append(filename)

        if not attachments:
            print("\n✅ No attachments found")
            return

        print(f"\nFound {len(attachments)} attachment(s):")
        red_flags = []

        for filename in attachments:
            print(f"  - {filename}")

            # Check for suspicious file extensions
            suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.vbs', '.js']
            if any(filename.lower().endswith(ext) for ext in suspicious_extensions):
                red_flags.append(f"⚠️  Executable attachment: {filename}")
                self.risk_score += 4

            # Check for double extensions
            if filename.count('.') > 1:
                red_flags.append(f"⚠️  Multiple file extensions (possible obfuscation): {filename}")
                self.risk_score += 2

            # Check for Office documents (potential macro malware)
            office_extensions = ['.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm']
            if any(filename.lower().endswith(ext) for ext in office_extensions):
                if filename.lower().endswith('m'):  # macro-enabled
                    red_flags.append(f"⚠️  Macro-enabled Office document: {filename}")
                    self.risk_score += 3

        if red_flags:
            print("\n🚨 ATTACHMENT RED FLAGS FOUND:")
            for flag in red_flags:
                print(f"  {flag}")
            self.indicators.extend(red_flags)

    def generate_report(self):
        """Generate final phishing analysis report"""
        print("\n" + "=" * 70)
        print("PHISHING ANALYSIS SUMMARY")
        print("=" * 70)

        print(f"\nEmail File: {self.email_file}")
        print(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\nTotal Red Flags Found: {len(self.indicators)}")
        print(f"Risk Score: {self.risk_score}/30")

        # Determine risk level
        if self.risk_score >= 15:
            risk_level = "🔴 CRITICAL - Highly likely phishing"
        elif self.risk_score >= 8:
            risk_level = "🟠 HIGH - Likely phishing"
        elif self.risk_score >= 4:
            risk_level = "🟡 MEDIUM - Suspicious, investigate further"
        else:
            risk_level = "🟢 LOW - Appears legitimate"

        print(f"\nRisk Assessment: {risk_level}")

        if self.indicators:
            print("\n📋 All Indicators Found:")
            for i, indicator in enumerate(self.indicators, 1):
                print(f"  {i}. {indicator}")

        print("\n" + "=" * 70)
        print("RECOMMENDATIONS")
        print("=" * 70)

        if self.risk_score >= 8:
            print("""
❌ DO NOT:
  - Click any links in this email
  - Download any attachments
  - Reply to this email
  - Provide any personal information

✅ DO:
  - Delete this email immediately
  - Report to your IT/Security team
  - Contact the supposed sender through official channels
  - Run antivirus scan if you interacted with this email
            """)
        else:
            print("""
⚠️ Exercise caution:
  - Verify sender through independent channels
  - Hover over links before clicking
  - Be wary of urgent requests
  - When in doubt, don't interact with the email
            """)

        # Save report to file
        self.save_report()

    def save_report(self):
        """Save analysis report to file"""
        os.makedirs('reports', exist_ok=True)

        filename = os.path.basename(self.email_file)
        report_file = f"reports/analysis_{filename.replace('.eml', '')}.txt"

        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("PHISHING EMAIL ANALYSIS REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Email File: {self.email_file}\n")
            f.write(f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Risk Score: {self.risk_score}/30\n\n")

            f.write("INDICATORS FOUND:\n")
            f.write("-"*70 + "\n")
            for i, indicator in enumerate(self.indicators, 1):
                f.write(f"{i}. {indicator}\n")

            f.write("\n" + "="*70 + "\n")

        print(f"\n💾 Report saved to: {report_file}")

    def analyze(self):
        """Run complete analysis"""
        if not self.load_email():
            return False

        print("\n" + "="*70)
        print("PHISHING EMAIL ANALYZER")
        print("="*70)
        print(f"Analyzing: {self.email_file}")

        self.analyze_sender()
        self.analyze_headers()
        self.analyze_links()
        self.analyze_content()
        self.analyze_attachments()
        self.generate_report()

        return True


def main():
    """Main function"""
    print("="*70)
    print("PHISHING EMAIL ANALYZER - Educational Tool")
    print("="*70)

    if len(sys.argv) < 2:
        print("\nUsage: python3 email_analyzer.py <email_file.eml>")
        print("\nExample: python3 email_analyzer.py samples/phishing_sample_1.eml")
        sys.exit(1)

    email_file = sys.argv[1]

    if not os.path.exists(email_file):
        print(f"\n[!] Error: File '{email_file}' not found")
        sys.exit(1)

    analyzer = PhishingAnalyzer(email_file)
    analyzer.analyze()


if __name__ == '__main__':
    main()
