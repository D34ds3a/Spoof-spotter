UNAPPROVED_DOMAIN_WEIGHT = 10
SIMILAR_DOMAIN_WEIGHT = 30

BASE_DIGIT_WEIGHT = 10
BASE_SPECIAL_WEIGHT = 5

SUBDOMAIN_DIGIT_WEIGHT = 5
SUBDOMAIN_SPECIAL_WEIGHT = 5

NON_ASCII_WEIGHT = 5
HOMOGLYPH_WEIGHT = 25
MIXED_SCRIPT_WEIGHT = 25
PUNYCODE_WEIGHT = 5
HISTORICAL_IOC_WEIGHT = 50

THREATFOX_MATCH_WEIGHT = 45
THREATFOX_MEDIUM_CONFIDENCE_WEIGHT = 5
THREATFOX_HIGH_CONFIDENCE_WEIGHT = 10

VIRUSTOTAL_ONE_MALICIOUS_WEIGHT = 5
VIRUSTOTAL_MEDIUM_MALICIOUS_WEIGHT = 10
VIRUSTOTAL_HIGH_MALICIOUS_WEIGHT = 20
VIRUSTOTAL_VERY_HIGH_MALICIOUS_WEIGHT = 30
VIRUSTOTAL_SUSPICIOUS_CONSENSUS_WEIGHT = 5
VIRUSTOTAL_PHISHING_CONSENSUS_WEIGHT = 10

URLHAUS_ONLINE_URL_WEIGHT = 40
URLHAUS_OFFLINE_URL_WEIGHT = 25
URLHAUS_ACTIVE_HOST_WEIGHT = 25
URLHAUS_HISTORICAL_HOST_WEIGHT = 10

LOCAL_THREATFOX_FRESH_WEIGHT = 40
LOCAL_THREATFOX_STALE_WEIGHT = 30

def get_risk_level(score):
    if score < 25:
        return "LOW"

    if score < 50:
        return "MODERATE"

    if score < 75:
        return "HIGH"

    return "CRITICAL"

def scored_local_matches(local_intel_result, threatfox_result):
    """
    The local ThreatFox matches that should add to the risk score.

    The local list is a copy of ThreatFox data, so it must not count
    twice when the live ThreatFox lookup already matched. When the
    live lookup ran and found nothing for the base domain, its newer
    answer wins for the base domain, but local matches on a subdomain
    or full URL still count because the live lookup does not check
    those.
    """
    if not local_intel_result:
        return []

    if not (
        local_intel_result.get("available")
        and local_intel_result.get("matched")
    ):
        return []

    if threatfox_result and threatfox_result.get("matched"):
        return []

    matches = local_intel_result.get("matches") or []

    live_checked = bool(
        threatfox_result
        and threatfox_result.get("available")
    )

    if live_checked:
        matches = [
            match
            for match in matches
            if match.get("matched_on") != "base_domain"
        ]

    return matches


def local_intel_score(local_intel_result, threatfox_result):
    """Returns (points, reason) for a local ThreatFox list match."""
    if not scored_local_matches(
        local_intel_result,
        threatfox_result,
    ):
        return 0, ""

    if local_intel_result.get("freshness") == "fresh":
        return (
            LOCAL_THREATFOX_FRESH_WEIGHT,
            "The local ThreatFox list (updated within the last "
            "24 hours) contains this indicator.",
        )

    return (
        LOCAL_THREATFOX_STALE_WEIGHT,
        "The local ThreatFox list contains this indicator, "
        "but the list is more than 24 hours old.",
    )


def calculate_risk(
    approved_match,
    similar_match=False,
    base_digits=None,
    base_special_characters=None,
    subdomain_digits=None,
    subdomain_special_characters=None,
    non_ascii_characters=None,
    homoglyphs=None,
    mixed_script_labels=None,
    punycode_detected=False,
    historical_ioc_match=False,
    threatfox_result=None,
    virustotal_result=None,
    urlhaus_result=None,
    local_intel_result=None,
):
    score = 0
    reasons = []

    if not approved_match:
        score += UNAPPROVED_DOMAIN_WEIGHT
        reasons.append("Base domain does not match an approved domain.")

    if not approved_match and similar_match:
        score += SIMILAR_DOMAIN_WEIGHT
        reasons.append("Base domain closely resembles a reference domain.")

    if base_digits:
        score += BASE_DIGIT_WEIGHT
        reasons.append("Base domain contains one or more ASCII digits.")

    if base_special_characters:
        score += BASE_SPECIAL_WEIGHT
        reasons.append("Base domain contains special characters.")

    if subdomain_digits:
        score += SUBDOMAIN_DIGIT_WEIGHT
        reasons.append("Subdomain contains one or more ASCII digits.")

    if subdomain_special_characters:
        score += SUBDOMAIN_SPECIAL_WEIGHT
        reasons.append("Subdomain contains special characters.")

    if non_ascii_characters:
        score += NON_ASCII_WEIGHT
        reasons.append("Domain contains non-ASCII characters.")

    if homoglyphs:
        score += HOMOGLYPH_WEIGHT
        reasons.append("Potential Unicode homoglyphs were detected.")

    if mixed_script_labels:
        score += MIXED_SCRIPT_WEIGHT
        reasons.append("A domain label mixes multiple writing scripts.")

    if punycode_detected:
        score += PUNYCODE_WEIGHT
        reasons.append("Punycode representation was detected.")

    if historical_ioc_match:
        score += HISTORICAL_IOC_WEIGHT
        reasons.append("Base domain appears in a historical IOC dataset.")

    if threatfox_result and threatfox_result.get("matched"):
        score += THREATFOX_MATCH_WEIGHT

        reasons.append(
            "ThreatFox currently returns the base domain "
            "as a threat-intelligence IOC."
        )

        confidence_values = []

        for finding in threatfox_result.get("results", []):
            confidence = finding.get("confidence")

            if isinstance(confidence, (int, float)):
                confidence_values.append(confidence)

        if confidence_values:
            highest_confidence = max(confidence_values)

            if highest_confidence >= 80:
                score += THREATFOX_HIGH_CONFIDENCE_WEIGHT

                reasons.append(
                    "ThreatFox reports high confidence "
                    "for the IOC match."
                )

            elif highest_confidence >= 50:
                score += THREATFOX_MEDIUM_CONFIDENCE_WEIGHT

                reasons.append(
                    "ThreatFox reports moderate confidence "
                    "for the IOC match."
                )

    if (
        virustotal_result
        and virustotal_result.get("available")
        and virustotal_result.get("query_status") == "ok"
    ):
        stats = virustotal_result.get("stats") or {}

        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)

        if isinstance(malicious_count, bool) or not isinstance(
            malicious_count,
            int,
        ):
            malicious_count = 0

        if isinstance(suspicious_count, bool) or not isinstance(
            suspicious_count,
            int,
        ):
            suspicious_count = 0

        malicious_count = max(malicious_count, 0)
        suspicious_count = max(suspicious_count, 0)

        if malicious_count >= 10:
            score += VIRUSTOTAL_VERY_HIGH_MALICIOUS_WEIGHT
            reasons.append(
                "VirusTotal reports malicious verdicts from "
                "10 or more security vendors."
            )

        elif malicious_count >= 5:
            score += VIRUSTOTAL_HIGH_MALICIOUS_WEIGHT
            reasons.append(
                "VirusTotal reports malicious verdicts from "
                "5 to 9 security vendors."
            )

        elif malicious_count >= 2:
            score += VIRUSTOTAL_MEDIUM_MALICIOUS_WEIGHT
            reasons.append(
                "VirusTotal reports malicious verdicts from "
                "2 to 4 security vendors."
            )

        elif malicious_count == 1:
            score += VIRUSTOTAL_ONE_MALICIOUS_WEIGHT
            reasons.append(
                "VirusTotal reports one malicious vendor verdict."
            )

        if suspicious_count >= 2:
            score += VIRUSTOTAL_SUSPICIOUS_CONSENSUS_WEIGHT
            reasons.append(
                "VirusTotal reports suspicious verdicts from "
                "multiple security vendors."
            )

        phishing_vendors = (
            virustotal_result.get("phishing_vendors")
            or []
        )

        if len(phishing_vendors) >= 2:
            score += VIRUSTOTAL_PHISHING_CONSENSUS_WEIGHT
            reasons.append(
                "Multiple VirusTotal vendors specifically "
                "report phishing."
            )

    if (
        urlhaus_result
        and urlhaus_result.get("available")
        and urlhaus_result.get("matched")
        and urlhaus_result.get("query_status") == "ok"
    ):
        lookup_type = urlhaus_result.get("lookup_type")
        details = urlhaus_result.get("details") or {}

        if lookup_type == "url":
            url_status = str(
                details.get("url_status") or ""
            ).strip().lower()

            if url_status == "online":
                score += URLHAUS_ONLINE_URL_WEIGHT
                reasons.append(
                    "URLhaus currently lists the submitted URL "
                    "as online malware-distribution infrastructure."
                )

            else:
                score += URLHAUS_OFFLINE_URL_WEIGHT
                reasons.append(
                    "URLhaus lists the submitted URL as malware-"
                    "distribution infrastructure."
                )

        elif lookup_type == "domain":
            online_url_count = details.get(
                "online_url_count",
                0,
            )
            url_count = details.get(
                "url_count",
                0,
            )

            if isinstance(online_url_count, bool) or not isinstance(
                online_url_count,
                int,
            ):
                online_url_count = 0

            if isinstance(url_count, bool) or not isinstance(
                url_count,
                int,
            ):
                url_count = 0

            online_url_count = max(online_url_count, 0)
            url_count = max(url_count, 0)

            if online_url_count > 0:
                score += URLHAUS_ACTIVE_HOST_WEIGHT
                reasons.append(
                    "URLhaus reports one or more currently online "
                    "malware URLs associated with the host."
                )

            elif url_count > 0:
                score += URLHAUS_HISTORICAL_HOST_WEIGHT
                reasons.append(
                    "URLhaus reports historical malware URLs "
                    "associated with the host."
                )

            else:
                score += URLHAUS_HISTORICAL_HOST_WEIGHT
                reasons.append(
                    "URLhaus returns a host-level threat-intelligence "
                    "match for the submitted host."
                )

    local_points, local_reason = local_intel_score(
        local_intel_result,
        threatfox_result,
    )

    if local_points:
        score += local_points
        reasons.append(local_reason)

    score = min(score, 100)

    risk_level = get_risk_level(score)

    return score, risk_level, reasons