import re
import ipaddress
from urllib.parse import urlparse


class ThreatChecker:

    def __init__(self):

        self.max_score = 100

        # ==================================================
        # TRUSTED DOMAINS
        # ==================================================

        self.trusted_domains = {
            "google.com",
            "google.co.in",
            "microsoft.com",
            "apple.com",
            "github.com",
            "wikipedia.org",
            "youtube.com",
            "amazon.com",
            "amazon.in",
            "linkedin.com",
            "python.org",
            "mozilla.org",
            "cloudflare.com"
        }

        # ==================================================
        # DEMO MALICIOUS INDICATORS
        # 14 PROJECT THREATS
        # ==================================================

        self.demo_threats = {

            # ==================================================
            # 1. BOTNET COMMAND AND CONTROL ACTIVITY
            # ==================================================

            "203.0.113.50": {
                "type": "ip",
                "score": 98,
                "confidence": 99,
                "status": "Critical",
                "threat_type": "Botnet",
                "reason": (
                    "Synthetic botnet command-and-control IP "
                    "indicator detected. This indicator is used "
                    "for cybersecurity threat intelligence "
                    "demonstration."
                )
            },

            # ==================================================
            # 2. FAKE BANKING LOGIN PAGE
            # ==================================================

            "fakebanking.com": {
                "type": "domain",
                "score": 85,
                "confidence": 95,
                "status": "Critical",
                "threat_type": "Phishing",
                "reason": (
                    "Synthetic phishing domain detected. "
                    "The domain represents a fake banking login "
                    "page designed to steal usernames, passwords "
                    "and OTPs."
                )
            },

            # ==================================================
            # 3. RANSOMWARE ATTACK DETECTED
            # ==================================================

            "ransomware-test.com": {
                "type": "domain",
                "score": 98,
                "confidence": 99,
                "status": "Critical",
                "threat_type": "Ransomware",
                "reason": (
                    "Synthetic ransomware indicator detected. "
                    "The domain represents ransomware activity "
                    "used for cybersecurity testing."
                )
            },

            # ==================================================
            # 4. SQL INJECTION ATTACK
            # ==================================================

            "http://sql-injection-test.example": {
                "type": "url",
                "score": 95,
                "confidence": 98,
                "status": "Critical",
                "threat_type": "SQL Injection",
                "reason": (
                    "Synthetic SQL injection URL indicator "
                    "detected. The indicator represents a "
                    "malicious web endpoint used for SQL "
                    "injection attack demonstration."
                )
            },

            # ==================================================
            # 5. MALWARE FILE HASH DETECTION
            # ==================================================

            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
                "type": "hash",
                "score": 100,
                "confidence": 100,
                "status": "Critical",
                "threat_type": "Trojan",
                "reason": (
                    "Synthetic malicious SHA-256 hash detected. "
                    "The hash is included as a demonstration "
                    "indicator for malware and Trojan threat "
                    "intelligence."
                )
            },

            # ==================================================
            # 6. FAKE MICROSOFT OFFICE ACTIVATION SCAM
            # ==================================================

            "office-activation-test.example": {
                "type": "domain",
                "score": 95,
                "confidence": 98,
                "status": "Critical",
                "threat_type": "Phishing",
                "reason": (
                    "Synthetic Microsoft Office activation scam "
                    "indicator detected. The domain represents "
                    "a fake activation page designed to deceive "
                    "users."
                )
            },

            # ==================================================
            # 7. SUSPICIOUS BROWSER EXTENSION ACTIVITY
            # ==================================================

            "browser-extension-spyware.example": {
                "type": "domain",
                "score": 92,
                "confidence": 97,
                "status": "Critical",
                "threat_type": "Spyware",
                "reason": (
                    "Synthetic spyware indicator detected. "
                    "The domain represents a suspicious browser "
                    "extension associated with potentially "
                    "unauthorized monitoring or data collection."
                )
            },

            # ==================================================
            # 8. SUSPICIOUS POWERSHELL SCRIPT EXECUTION
            # ==================================================

            "http://powershell-malware-test.example": {
                "type": "url",
                "score": 94,
                "confidence": 98,
                "status": "Critical",
                "threat_type": "Malware",
                "reason": (
                    "Synthetic malicious PowerShell execution "
                    "indicator detected. The URL represents a "
                    "test endpoint used for malware execution "
                    "demonstration."
                )
            },

            # ==================================================
            # 9. WANNACRY RANSOMWARE ATTACK
            # ==================================================

            "wannacry-test.example": {
                "type": "domain",
                "score": 100,
                "confidence": 100,
                "status": "Critical",
                "threat_type": "Ransomware",
                "reason": (
                    "Synthetic WannaCry ransomware indicator "
                    "detected. The domain is used for "
                    "cybersecurity threat intelligence "
                    "demonstration."
                )
            },

            # ==================================================
            # 10. MIRAI BOTNET COMMAND SERVER
            # ==================================================

            "198.51.100.77": {
                "type": "ip",
                "score": 94,
                "confidence": 98,
                "status": "Critical",
                "threat_type": "Botnet",
                "reason": (
                    "Synthetic Mirai botnet command-server IP "
                    "indicator detected. The IP is used for "
                    "cybersecurity threat intelligence "
                    "demonstration."
                )
            },

            # ==================================================
            # 11. ZEUS BANKING TROJAN
            # ==================================================

            "zeus-banking-trojan.example": {
                "type": "domain",
                "score": 97,
                "confidence": 99,
                "status": "Critical",
                "threat_type": "Trojan",
                "reason": (
                    "Synthetic Zeus banking Trojan indicator "
                    "detected. The domain represents a banking "
                    "malware test indicator used for "
                    "cybersecurity demonstration."
                )
            },

            # ==================================================
            # 12. PHISHING LOGIN CAMPAIGN
            # ==================================================

            "http://phishing-login-test.example": {
                "type": "url",
                "score": 95,
                "confidence": 98,
                "status": "Critical",
                "threat_type": "Phishing",
                "reason": (
                    "Synthetic phishing login campaign indicator "
                    "detected. The URL represents a fraudulent "
                    "login endpoint designed for credential "
                    "theft demonstration."
                )
            },

            "test-login-example.com": {
                "type": "domain",
                "score": 90,
                "confidence": 97,
                "status": "Critical",
                "threat_type": "Phishing",
                "reason": (
                    "Synthetic phishing test domain detected. "
                    "The domain represents a simulated fraudulent "
                    "login page used for cybersecurity threat "
                    "detection and demonstration."
                )
            },

            # ==================================================
            # 13. MALWARE COMMAND AND CONTROL ACTIVITY
            # ==================================================

            "192.0.2.123": {
                "type": "ip",
                "score": 96,
                "confidence": 99,
                "status": "Critical",
                "threat_type": "Malware",
                "reason": (
                    "Synthetic malware command-and-control IP "
                    "indicator detected. The IP is used for "
                    "cybersecurity threat intelligence testing."
                )
            },

            # ==================================================
            # 14. TEST SUSPICIOUS LOGIN
            # ==================================================

            "suspicious-login-test.example": {
                "type": "domain",
                "score": 90,
                "confidence": 97,
                "status": "Critical",
                "threat_type": "Phishing",
                "reason": (
                    "Synthetic suspicious login indicator "
                    "detected. The domain represents a phishing "
                    "test indicator used for login-threat "
                    "detection demonstration."
                )
            }
        }

        # ==================================================
        # CATEGORY SCORES
        # ==================================================

        self.category_scores = {
            "phishing": 25,
            "malware": 30,
            "ransomware": 35,
            "trojan": 30,
            "spyware": 30,
            "botnet": 30,
            "ddos": 25,
            "exploit": 30,
            "backdoor": 30,
            "virus": 30
        }

        # ==================================================
        # SEVERITY SCORES
        # ==================================================

        self.severity_scores = {
            "low": 5,
            "medium": 15,
            "high": 25,
            "critical": 35
        }

    # ======================================================
    # MAIN CHECK FUNCTION
    # ======================================================

    def check(
        self,
        indicator_type,
        value,
        title="",
        category="",
        severity="",
        description=""
    ):

        indicator_type = str(
            indicator_type or ""
        ).strip().lower()

        value = str(
            value or ""
        ).strip()

        title = str(
            title or ""
        ).strip()

        category = str(
            category or ""
        ).strip().lower()

        severity = str(
            severity or ""
        ).strip().lower()

        description = str(
            description or ""
        ).strip().lower()

        # ==================================================
        # EMPTY VALUE
        # ==================================================

        if not value:

            return self._result(
                score=0,
                confidence=0,
                status="Unknown",
                reason="No indicator was provided.",
                recommendation="Please enter a valid indicator."
            )

        # ==================================================
        # VALID INDICATOR TYPES
        # ==================================================

        valid_types = {
            "url",
            "domain",
            "ip",
            "email",
            "hash",
            "sha256",
            "sha-256",
            "md5",
            "sha1",
            "sha-1"
        }

        # ==================================================
        # BACKWARD COMPATIBILITY
        # ==================================================

        if indicator_type not in valid_types:

            possible_category = indicator_type

            detected_type = self.detect_indicator_type(
                value
            )

            if possible_category in self.category_scores:

                if not category:
                    category = possible_category

            indicator_type = detected_type

        # ==================================================
        # NORMALIZE HASH TYPES
        # ==================================================

        if indicator_type in {
            "sha256",
            "sha-256",
            "sha1",
            "sha-1",
            "md5"
        }:

            indicator_type = "hash"

        # ==================================================
        # NORMALIZE INDICATOR
        # ==================================================

        normalized = self.normalize_indicator(
            indicator_type,
            value
        )

        # ==================================================
        # DEMO THREAT CHECK
        # ==================================================

        demo = self.demo_threats.get(
            normalized
        )

        if demo:

            if demo["type"] == indicator_type:

                return {
                    "indicator": value,
                    "indicator_type": indicator_type,
                    "status": demo["status"],
                    "score": demo["score"],
                    "confidence": demo["confidence"],
                    "threat_type": demo.get(
                        "threat_type",
                        "Unknown"
                    ),
                    "reason": demo["reason"],
                    "recommendation": (
                        "Critical threat detected. "
                        "Do not interact with this indicator. "
                        "Block or isolate it if appropriate."
                    )
                }

        # ==================================================
        # TRUSTED DOMAIN CHECK
        # ==================================================

        if indicator_type in {
            "url",
            "domain"
        }:

            hostname = self.extract_hostname(
                value
            )

            if self.is_trusted_domain(
                hostname
            ):

                return {
                    "indicator": value,
                    "indicator_type": indicator_type,
                    "status": "Safe",
                    "score": 0,
                    "confidence": 100,
                    "threat_type": "Trusted Domain",
                    "reason": (
                        "The domain matches the project's "
                        "trusted-domain list and no suspicious "
                        "characteristics were detected."
                    ),
                    "recommendation": (
                        "No risk detected. "
                        "This indicator is verified as trusted."
                    )
                }

        # ==================================================
        # GENERAL HEURISTIC ANALYSIS
        # ==================================================

        score = 0
        reasons = []

        # ==================================================
        # TYPE-SPECIFIC ANALYSIS
        # ==================================================

        if indicator_type == "url":

            score += self.check_url(
                value,
                reasons
            )

        elif indicator_type == "domain":

            score += self.check_domain(
                value,
                reasons
            )

        elif indicator_type == "ip":

            score += self.check_ip(
                value,
                reasons
            )

        elif indicator_type == "email":

            score += self.check_email(
                value,
                reasons
            )

        elif indicator_type == "hash":

            score += self.check_hash(
                value,
                reasons
            )

        else:

            score += 20

            reasons.append(
                "Unknown indicator type."
            )

        # ==================================================
        # CATEGORY ANALYSIS
        # ==================================================

        if category in self.category_scores:

            score += self.category_scores[
                category
            ]

            reasons.append(
                f"Threat category '{category}' "
                "increases the risk score."
            )

        # ==================================================
        # SEVERITY ANALYSIS
        # ==================================================

        if severity in self.severity_scores:

            score += self.severity_scores[
                severity
            ]

            reasons.append(
                f"Reported severity is {severity}."
            )

        # ==================================================
        # TITLE ANALYSIS
        # ==================================================

        suspicious_title_words = {

            "phishing",
            "malware",
            "ransomware",
            "trojan",
            "spyware",
            "botnet",
            "ddos",
            "attack",
            "exploit",
            "malicious",
            "fraud",
            "scam",
            "virus",
            "backdoor",
            "credential",
            "stealing",
            "stealer"
        }

        title_words = set(
            re.findall(
                r"[a-zA-Z]+",
                title.lower()
            )
        )

        title_matches = (
            title_words
            & suspicious_title_words
        )

        if title_matches:

            score += min(
                len(title_matches) * 8,
                20
            )

            reasons.append(
                "Threat title contains suspicious "
                "security-related terms."
            )

        # ==================================================
        # DESCRIPTION ANALYSIS
        # ==================================================

        suspicious_description_words = {

            "malware",
            "phishing",
            "ransomware",
            "trojan",
            "spyware",
            "payload",
            "command and control",
            "c2",
            "backdoor",
            "malicious",
            "attack",
            "compromised",
            "fraud",
            "scam",
            "credential theft",
            "password theft",
            "data theft",
            "steal passwords",
            "steals passwords",
            "financial information",
            "otp",
            "unauthorized access",
            "remote access"
        }

        description_matches = 0

        for word in suspicious_description_words:

            if word in description:

                description_matches += 1

        if description_matches:

            score += min(
                description_matches * 6,
                25
            )

            reasons.append(
                "Threat description contains "
                "suspicious characteristics."
            )

        # ==================================================
        # COMBINED MALICIOUS SIGNAL
        # ==================================================

        strong_signals = 0

        if category in {
            "malware",
            "ransomware",
            "trojan",
            "spyware",
            "botnet",
            "phishing",
            "backdoor",
            "exploit",
            "virus"
        }:

            strong_signals += 1

        if severity in {
            "high",
            "critical"
        }:

            strong_signals += 1

        if title_matches:

            strong_signals += 1

        if description_matches >= 2:

            strong_signals += 1

        if strong_signals >= 3:

            score += 15

            reasons.append(
                "Multiple strong threat indicators "
                "were detected."
            )

        # ==================================================
        # LIMIT SCORE
        # ==================================================

        score = min(
            max(score, 0),
            self.max_score
        )

        # ==================================================
        # STATUS
        # ==================================================

        status = self.get_status(
            score
        )

        # ==================================================
        # CONFIDENCE
        # ==================================================

        confidence = self.calculate_confidence(
            score,
            indicator_type,
            category,
            severity,
            len(reasons)
        )

        # ==================================================
        # REASON
        # ==================================================

        if reasons:

            unique_reasons = list(
                dict.fromkeys(reasons)
            )

            reason = " ".join(
                unique_reasons
            )

        else:

            reason = (
                "No significant suspicious "
                "characteristics were detected."
            )

        # ==================================================
        # RECOMMENDATION
        # ==================================================

        recommendation = self.get_recommendation(
            score
        )

        # ==================================================
        # THREAT TYPE
        # ==================================================

        if category:

            threat_type = category.title()

        else:

            threat_type = "General Threat"

        # ==================================================
        # FINAL RESULT
        # ==================================================

        return {

            "indicator": value,

            "indicator_type": indicator_type,

            "status": status,

            "score": score,

            "confidence": confidence,

            "threat_type": threat_type,

            "reason": reason,

            "recommendation": recommendation

        }

    # ======================================================
    # DETECT INDICATOR TYPE
    # ======================================================

    def detect_indicator_type(
        self,
        value
    ):

        value = str(
            value or ""
        ).strip()

        # --------------------------------------------------
        # EMAIL
        # --------------------------------------------------

        if re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+",
            value
        ):

            return "email"

        # --------------------------------------------------
        # IP
        # --------------------------------------------------

        try:

            ipaddress.ip_address(
                value
            )

            return "ip"

        except ValueError:

            pass

        # --------------------------------------------------
        # HASH
        # --------------------------------------------------

        if re.fullmatch(
            r"[A-Fa-f0-9]{32}",
            value
        ):

            return "hash"

        if re.fullmatch(
            r"[A-Fa-f0-9]{40}",
            value
        ):

            return "hash"

        if re.fullmatch(
            r"[A-Fa-f0-9]{64}",
            value
        ):

            return "hash"

        # --------------------------------------------------
        # URL
        # --------------------------------------------------

        lowered = value.lower()

        if (
            lowered.startswith("http://")
            or lowered.startswith("https://")
            or lowered.startswith("www.")
        ):

            return "url"

        # --------------------------------------------------
        # DOMAIN
        # --------------------------------------------------

        if re.fullmatch(
            r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            value
        ):

            return "domain"

        # --------------------------------------------------
        # DEFAULT
        # --------------------------------------------------

        return "unknown"

    # ======================================================
    # NORMALIZE INDICATOR
    # ======================================================

    def normalize_indicator(
        self,
        indicator_type,
        value
    ):

        value = value.strip().lower()

        if indicator_type == "url":

            value = value.rstrip("/")

        return value

    # ======================================================
    # EXTRACT HOSTNAME
    # ======================================================

    def extract_hostname(
        self,
        value
    ):

        try:

            value = value.strip()

            if "://" not in value:

                value = "https://" + value

            parsed = urlparse(
                value
            )

            return (
                parsed.hostname or ""
            ).lower().rstrip(".")

        except Exception:

            return ""

    # ======================================================
    # TRUSTED DOMAIN
    # ======================================================

    def is_trusted_domain(
        self,
        hostname
    ):

        if not hostname:

            return False

        hostname = hostname.lower().rstrip(".")

        for trusted in self.trusted_domains:

            if (
                hostname == trusted
                or hostname.endswith(
                    "." + trusted
                )
            ):

                return True

        return False

    # ======================================================
    # URL CHECK
    # ======================================================

    def check_url(
        self,
        value,
        reasons
    ):

        score = 5

        try:

            parsed = urlparse(
                value
            )

            hostname = (
                parsed.hostname or ""
            ).lower()

            # --------------------------------------------------
            # HTTP
            # --------------------------------------------------

            if parsed.scheme.lower() == "http":

                score += 10

                reasons.append(
                    "URL uses unencrypted HTTP."
                )

            # --------------------------------------------------
            # @ SYMBOL
            # --------------------------------------------------

            if "@" in parsed.netloc:

                score += 15

                reasons.append(
                    "URL contains an embedded username."
                )

            # --------------------------------------------------
            # LONG URL
            # --------------------------------------------------

            if len(value) > 100:

                score += 10

                reasons.append(
                    "URL is unusually long."
                )

            # --------------------------------------------------
            # SUSPICIOUS TERMS
            # --------------------------------------------------

            suspicious_terms = {

                "login",
                "verify",
                "verification",
                "account",
                "password",
                "secure",
                "update",
                "confirm",
                "bank",
                "wallet",
                "payment",
                "credential",
                "reset",
                "signin",
                "authenticate",
                "security-alert",
                "phishing"
            }

            matches = [
                term
                for term in suspicious_terms
                if term in value.lower()
            ]

            if matches:

                score += min(
                    len(matches) * 6,
                    35
                )

                reasons.append(
                    "URL contains terms commonly "
                    "associated with phishing."
                )

            # --------------------------------------------------
            # DEEP SUBDOMAIN
            # --------------------------------------------------

            if hostname.count(".") >= 4:

                score += 10

                reasons.append(
                    "URL contains an unusually "
                    "deep subdomain structure."
                )

            # --------------------------------------------------
            # MANY HYPHENS
            # --------------------------------------------------

            if hostname.count("-") >= 3:

                score += 10

                reasons.append(
                    "URL hostname contains multiple hyphens."
                )

        except Exception:

            score += 15

            reasons.append(
                "URL structure could not be analyzed."
            )

        return score

    # ======================================================
    # DOMAIN CHECK
    # ======================================================

    def check_domain(
        self,
        value,
        reasons
    ):

        score = 5

        domain = value.lower()

        suspicious_terms = {

            "login",
            "verify",
            "verification",
            "secure",
            "account",
            "update",
            "payment",
            "wallet",
            "bank",
            "credential",
            "password",
            "reset",
            "signin",
            "security",
            "phishing",
            "malware",
            "attack",
            "confirm"
        }

        matches = [
            term
            for term in suspicious_terms
            if term in domain
        ]

        if matches:

            score += min(
                len(matches) * 6,
                35
            )

            reasons.append(
                "Domain contains potentially "
                "suspicious keywords."
            )

        if len(domain) > 50:

            score += 10

            reasons.append(
                "Domain name is unusually long."
            )

        if domain.count("-") >= 3:

            score += 10

            reasons.append(
                "Domain contains multiple hyphens."
            )

        return score

    # ======================================================
    # IP CHECK
    # ======================================================

    def check_ip(
        self,
        value,
        reasons
    ):

        try:

            ip = ipaddress.ip_address(
                value
            )

            if ip.is_private:

                reasons.append(
                    "Private IP address detected."
                )

                return 0

            if ip.is_loopback:

                reasons.append(
                    "Loopback IP address detected."
                )

                return 0

            if ip.is_reserved:

                reasons.append(
                    "Reserved IP address detected."
                )

                return 5

            reasons.append(
                "Publicly routable IP address detected."
            )

            return 15

        except ValueError:

            reasons.append(
                "Invalid IP address format."
            )

            return 30

    # ======================================================
    # EMAIL CHECK
    # ======================================================

    def check_email(
        self,
        value,
        reasons
    ):

        score = 5

        try:

            local_part, domain = value.lower().split(
                "@",
                1
            )

        except ValueError:

            reasons.append(
                "Invalid email address format."
            )

            return 30

        suspicious_terms = {

            "verify",
            "security",
            "support",
            "account",
            "payment",
            "alert",
            "login",
            "admin",
            "password",
            "reset",
            "urgent",
            "phishing",
            "fraud",
            "scam"
        }

        matches = [
            term
            for term in suspicious_terms
            if term in local_part
        ]

        if matches:

            score += min(
                len(matches) * 10,
                35
            )

            reasons.append(
                "Email address contains "
                "security/phishing-related terms."
            )

        suspicious_domains = {

            "phishing-test.example",
            "malware-test.example",
            "example.com"
        }

        if domain in suspicious_domains:

            score += 30

            reasons.append(
                "Email uses a suspicious or "
                "demonstration threat domain."
            )

        if len(local_part) > 30:

            score += 10

            reasons.append(
                "Email local-part is unusually long."
            )

        return score

    # ======================================================
    # HASH CHECK
    # ======================================================

    def check_hash(
        self,
        value,
        reasons
    ):

        # SHA-256

        if re.fullmatch(
            r"[A-Fa-f0-9]{64}",
            value
        ):

            reasons.append(
                "Valid SHA-256 hash format detected."
            )

            return 5

        # SHA-1

        if re.fullmatch(
            r"[A-Fa-f0-9]{40}",
            value
        ):

            reasons.append(
                "Valid SHA-1 hash format detected."
            )

            return 5

        # MD5

        if re.fullmatch(
            r"[A-Fa-f0-9]{32}",
            value
        ):

            reasons.append(
                "Valid MD5 hash format detected."
            )

            return 5

        reasons.append(
            "Invalid hash format."
        )

        return 30

    # ======================================================
    # STATUS
    # ======================================================

    def get_status(
        self,
        score
    ):

        if score >= 80:

            return "Critical"

        if score >= 60:

            return "Malicious"

        if score >= 30:

            return "Suspicious"

        return "Safe"

    # ======================================================
    # CONFIDENCE
    # ======================================================

    def calculate_confidence(
        self,
        score,
        indicator_type,
        category,
        severity,
        reason_count
    ):

        confidence = 50

        if indicator_type in {
            "ip",
            "url",
            "domain",
            "email",
            "hash"
        }:

            confidence += 10

        if category:

            confidence += 10

        if severity:

            confidence += 10

        if reason_count >= 2:

            confidence += 10

        elif reason_count == 1:

            confidence += 5

        if score >= 80:

            confidence += 10

        elif score >= 60:

            confidence += 5

        return min(
            confidence,
            100
        )

    # ======================================================
    # RECOMMENDATION
    # ======================================================

    def get_recommendation(
        self,
        score
    ):

        if score == 0:

            return (
                "No risk detected. "
                "This indicator is verified as trusted."
            )

        if score < 30:

            return (
                "Low risk. No major suspicious "
                "characteristics were detected."
            )

        if score < 60:

            return (
                "Suspicious indicator. "
                "Verify its source before interacting."
            )

        if score < 80:

            return (
                "High risk. Avoid interacting with "
                "this indicator unless independently verified."
            )

        return (
            "Critical risk. Do not interact with this "
            "indicator. Block or isolate it if appropriate."
        )

    # ======================================================
    # RESULT HELPER
    # ======================================================

    def _result(
        self,
        score,
        confidence,
        status,
        reason,
        recommendation
    ):

        return {

            "indicator": "",

            "indicator_type": "unknown",

            "status": status,

            "score": score,

            "confidence": confidence,

            "threat_type": "General Threat",

            "reason": reason,

            "recommendation": recommendation

        }