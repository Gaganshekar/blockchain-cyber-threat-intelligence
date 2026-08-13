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
        #
        # These are synthetic indicators for your MCA
        # project demonstration. They are NOT real
        # malicious infrastructure.
        # ==================================================

        self.demo_threats = {

    # ==================================================
    # MALICIOUS URL
    # ==================================================

    "http://login-verify-password-reset-test.example": {
        "type": "url",
        "score": 95,
        "confidence": 98,
        "status": "Critical",
        "threat_type": "Phishing",
        "reason": (
            "Synthetic phishing URL detected. "
            "Credential and password-reset terminology "
            "indicates a phishing threat."
        )
    },

    # ==================================================
    # MALICIOUS DOMAIN
    # ==================================================

    "login-verify-account-security-test.example": {
        "type": "domain",
        "score": 92,
        "confidence": 97,
        "status": "Critical",
        "threat_type": "Phishing",
        "reason": (
            "Synthetic phishing domain detected. "
            "Account verification and security terminology "
            "indicates a phishing threat."
        )
    },

    # ==================================================
    # MALICIOUS IP
    # ==================================================

    "203.0.113.50": {
        "type": "ip",
        "score": 98,
        "confidence": 99,
        "status": "Critical",
        "threat_type": "Malware / C2",
        "reason": (
            "Synthetic command-and-control IP indicator "
            "used for cybersecurity demonstration."
        )
    },

    # ==================================================
    # MALICIOUS EMAIL
    # ==================================================

    "urgent-security-alert@phishing-test.example": {
        "type": "email",
        "score": 90,
        "confidence": 96,
        "status": "Critical",
        "threat_type": "Phishing",
        "reason": (
            "Synthetic phishing email indicator detected. "
            "The address contains security-alert and "
            "phishing-related terminology."
        )
    },

    # ==================================================
    # MALICIOUS SHA-256
    # ==================================================

    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {
        "type": "hash",
        "score": 100,
        "confidence": 100,
        "status": "Critical",
        "threat_type": "Malware",
        "reason": (
            "Synthetic malicious SHA-256 indicator used "
            "for cybersecurity demonstration."
        )
    }
}

    # ==================================================
    # MAIN CHECK FUNCTION
    # ==================================================

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
        # NORMALIZE
        # ==================================================

        normalized = self.normalize_indicator(
            indicator_type,
            value
        )

        # ==================================================
        # DEMO MALICIOUS DATABASE
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
                    "threat_type": demo.get("threat_type", "Unknown"),
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
                    "threat_type": "General Threat",
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

        # --------------------------------------------------
        # TYPE-SPECIFIC ANALYSIS
        # --------------------------------------------------

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

        category_scores = {

            "phishing": 25,
            "malware": 30,
            "ransomware": 35,
            "trojan": 30,
            "spyware": 30,
            "ddos": 25,
            "botnet": 30

        }

        if category in category_scores:

            score += category_scores[
                category
            ]

            reasons.append(
                f"Threat category '{category}' "
                "increases the risk score."
            )

        # ==================================================
        # SEVERITY ANALYSIS
        # ==================================================

        severity_scores = {

            "low": 5,
            "medium": 15,
            "high": 25,
            "critical": 35

        }

        if severity in severity_scores:

            score += severity_scores[
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
            "scam"

        }

        title_words = set(
            re.findall(
                r"[a-zA-Z]+",
                title.lower()
            )
        )

        matches = (
            title_words
            & suspicious_title_words
        )

        if matches:

            score += min(
                len(matches) * 5,
                15
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
            "credential theft",
            "password theft",
            "exploit",
            "payload",
            "command and control",
            "c2",
            "backdoor",
            "malicious",
            "attack",
            "compromised",
            "fraud",
            "scam"

        }

        description_matches = 0

        for word in suspicious_description_words:

            if word in description:

                description_matches += 1

        if description_matches:

            score += min(
                description_matches * 5,
                20
            )

            reasons.append(
                "Threat description contains "
                "suspicious characteristics."
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

            reason = " ".join(
                reasons
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

        return {

            "indicator": value,

            "indicator_type": indicator_type,

            "status": status,

            "score": score,

            "confidence": confidence,

            "threat_type": category.title() if category else "General Threat",

            "reason": reason,

            "recommendation": recommendation

        }

    # ==================================================
    # NORMALIZE INDICATOR
    # ==================================================

    def normalize_indicator(
        self,
        indicator_type,
        value
    ):

        value = value.strip().lower()

        if indicator_type == "url":

            return value.rstrip("/")

        return value

    # ==================================================
    # EXTRACT HOSTNAME
    # ==================================================

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

    # ==================================================
    # TRUSTED DOMAIN
    # ==================================================

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

    # ==================================================
    # URL CHECK
    # ==================================================

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

            # HTTP
            if parsed.scheme.lower() == "http":

                score += 10

                reasons.append(
                    "URL uses unencrypted HTTP."
                )

            # @ symbol
            if "@" in parsed.netloc:

                score += 15

                reasons.append(
                    "URL contains an embedded username."
                )

            # Long URL
            if len(value) > 100:

                score += 10

                reasons.append(
                    "URL is unusually long."
                )

            # Suspicious terms
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
                "reset"

            }

            matches = [
                term
                for term in suspicious_terms
                if term in value.lower()
            ]

            if matches:

                score += min(
                    len(matches) * 5,
                    30
                )

                reasons.append(
                    "URL contains terms commonly "
                    "associated with phishing."
                )

            # Deep subdomain
            if hostname.count(".") >= 4:

                score += 10

                reasons.append(
                    "URL contains an unusually "
                    "deep subdomain structure."
                )

        except Exception:

            score += 15

            reasons.append(
                "URL structure could not be analyzed."
            )

        return score

    # ==================================================
    # DOMAIN CHECK
    # ==================================================

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
            "secure",
            "account",
            "update",
            "payment",
            "wallet",
            "bank",
            "credential",
            "password",
            "reset"

        }

        matches = [
            term
            for term in suspicious_terms
            if term in domain
        ]

        if matches:

            score += min(
                len(matches) * 5,
                30
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

    # ==================================================
    # IP CHECK
    # ==================================================

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

    # ==================================================
    # EMAIL CHECK
    # ==================================================

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
            "urgent"

        }

        matches = [
            term
            for term in suspicious_terms
            if term in local_part
        ]

        if matches:

            score += min(
                len(matches) * 10,
                30
            )

            reasons.append(
                "Email address contains "
                "security/phishing-related terms."
            )

        if len(local_part) > 30:

            score += 10

            reasons.append(
                "Email local-part is unusually long."
            )

        return score

    # ==================================================
    # HASH CHECK
    # ==================================================

    def check_hash(
        self,
        value,
        reasons
    ):

        if re.fullmatch(
            r"[A-Fa-f0-9]{64}",
            value
        ):

            reasons.append(
                "Valid SHA-256 hash format detected."
            )

            return 5

        reasons.append(
            "Invalid SHA-256 format."
        )

        return 30

    # ==================================================
    # STATUS
    # ==================================================

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

    # ==================================================
    # CONFIDENCE
    # ==================================================

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

        return min(
            confidence,
            100
        )

    # ==================================================
    # RECOMMENDATION
    # ==================================================

    def get_recommendation(
        self,
        score
    ):

        if score == 0:

            return (
                "No risk detected. "
                "This indicator is verified as trusted."
            )

        if score <= 10:

            return (
                "Low risk. No major suspicious "
                "characteristics were detected."
            )

        if score <= 30:

            return (
                "Proceed with caution and verify "
                "the indicator before interacting."
            )

        if score <= 60:

            return (
                "Suspicious indicator. "
                "Verify its source before interacting."
            )

        if score <= 80:

            return (
                "High risk. Avoid interacting with "
                "this indicator unless independently verified."
            )

        return (
            "Critical risk. Do not interact with this "
            "indicator. Block or isolate it if appropriate."
        )

    # ==================================================
    # RESULT HELPER
    # ==================================================

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