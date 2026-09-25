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

def get_risk_level(score):
    if score < 25:
        return "LOW"

    if score < 50:
        return "MODERATE"

    if score < 75:
        return "HIGH"

    return "CRITICAL"

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
):
    score = 0
    reasons = []

    if not approved_match:
        score += UNAPPROVED_DOMAIN_WEIGHT
        reasons.append("Base domain does not match an approved domain.")

    if not approved_match and similar_match:
        score += SIMILAR_DOMAIN_WEIGHT
        reasons.append("Base domain closely resembles an approved domain.")

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

    score = min(score, 100)

    risk_level = get_risk_level(score)

    return score, risk_level, reasons