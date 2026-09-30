from core.parser import (
    classify_input,
    parse_email,
    parse_domain,
    validate_email,
    validate_domain,
    extract_domain_parts,
)

from core.domain_checker import (
    load_approved_domains,
    is_approved_domain,
)

from core.similarity import (
    find_closest_domain,
    is_similar_reference_candidate,
)

from core.reference_domains import load_reference_domains

from core.character_checker import (
    find_digits,
    find_special_characters,
    find_non_ascii_characters,
    find_homoglyphs,
    find_mixed_script_labels,
    has_punycode,
    decode_punycode_domain,
)

from core.risk import calculate_risk

from core.report import generate_report

from core.threat_intel import (
    load_historical_sources,
    find_historical_ioc_sources,
    get_historical_ioc_details,
)
 
from core.threatfox import search_ioc

from core.privacy import (
    STANDARD_MODE,
    PRIVACY_MODE,
    allow_external_lookup,
    service_allowed,
)

from core.google_safe_browsing import (
    canonicalize_url,
    build_hash_candidates,
)

from core.google_safe_browsing_client import (
    search_hash_candidates,
)

from core.phishtank import (
    check_url,
)

def choose_analysis_mode():
    print()
    print("Analysis mode:")
    print("1. Standard")
    print("2. Privacy")

    choice = input(
        "Select mode [1]: "
    ).strip()

    if choice == "2":
        return PRIVACY_MODE

    return STANDARD_MODE

def main():
    print("=========================")
    print("      SPOOF SPOTTER")
    print("=========================")

    analysis_mode = choose_analysis_mode()

    user_input = input("\nEnter an email or website: ").strip()

    input_type = classify_input(user_input)

    approved_domains = load_approved_domains()
    reference_domains = load_reference_domains()

    historical_sources = load_historical_sources()

    email_address = None
    hostname = ""
    subdomain = ""
    base_domain = ""
    display_input_type = ""


    if input_type == "empty":
        print("\nError: No input was provided.")
        return

    elif input_type == "email":
        if not validate_email(user_input):
            print("\nError: Invalid email address.")
            return

        email_address, hostname = parse_email(user_input)

        subdomain, base_domain = extract_domain_parts(hostname)

        display_input_type = "EMAIL"

    elif input_type == "domain":
        if not validate_domain(user_input):
            print("\nError: Invalid domain or website.")
            return

        hostname = parse_domain(user_input)

        subdomain, base_domain = extract_domain_parts(user_input)

        display_input_type = "DOMAIN/WEBSITE"
   
    approved_match = is_approved_domain(
        base_domain,
        approved_domains
    )
   
    closest_reference_domain, similarity_score = find_closest_domain(
        base_domain,
        reference_domains
    )
           
    similar_match = (is_similar_reference_candidate(
        base_domain,
        closest_reference_domain,
        similarity_score,
        )
    )

    historical_ioc_sources = find_historical_ioc_sources(
        base_domain,
        historical_sources
    )

    historical_ioc_details = get_historical_ioc_details(
        base_domain,
        historical_sources
    )

    historical_ioc_match = bool(historical_ioc_details)

    external_lookup_allowed = (allow_external_lookup(hostname))

    threatfox_allowed = (
        service_allowed(
            "threatfox",
            analysis_mode,
        )
    )

    if (
        external_lookup_allowed
        and threatfox_allowed
    ):
        threatfox_result = search_ioc(base_domain)

    else:
        if not external_lookup_allowed:
            threatfox_status = ("external_lookup_blocked")
        else:
            threatfox_status = ("privacy_mode")

        threatfox_result = {
            "available": False,
            "matched": False,
            "query_status": (
                threatfox_status
            ),
            "results": [],
        }

    google_allowed = (
        service_allowed(
            "google_safe_browsing",
            analysis_mode,
        )
    )

    if (
        external_lookup_allowed
        and google_allowed
    ):
        if input_type == "email":
            google_input = hostname
        else:
            google_input = user_input

        canonical_google_url = (
            canonicalize_url(
                google_input
            )
        )

        if canonical_google_url:
            google_candidates = (
                build_hash_candidates(
                    canonical_google_url
                )
            )

            google_safe_browsing_result = (
                search_hash_candidates(
                    google_candidates
                )
            )

        else:
            google_safe_browsing_result = {
                "available": False,
                "matched": False,
                "query_status": ("invalid_input"),
                "matches": [],
                "cache_duration": None,
                "cache_status": ("not_checked"),
                "network_request_made": (False),
            }

    else:
        if not external_lookup_allowed:
            google_status = ("external_lookup_blocked")
        else:
            google_status = ("privacy_policy_blocked")

        google_safe_browsing_result = {
            "available": False,
            "matched": False,
            "query_status": (
                google_status
            ),
            "matches": [],
            "cache_duration": None,
            "cache_status": ("not_checked"),
            "network_request_made": (False),
        }

    phishtank_allowed = (
        service_allowed(
            "phishtank",
            analysis_mode,
        )
    )

    is_full_url = (
        user_input.lower().startswith("http://")
        or user_input.lower().startswith("https://")
    )

    if input_type == "email":
        phishtank_result = {
            "available": False,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": ("not_applicable_email"),
            "result": None,
        }

    elif not is_full_url:
        phishtank_result = {
            "available": False,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": ("full_url_required"),
            "result": None,
        }

    elif not external_lookup_allowed:
        phishtank_result = {
            "available": False,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": ("external_lookup_blocked"),
            "result": None,
        }

    elif not phishtank_allowed:
        phishtank_result = {
            "available": False,
            "matched": False,
            "listed": False,
            "source": "PhishTank",
            "query_status": ("privacy_mode"),
            "result": None,
        }

    else:
        phishtank_result = check_url(
            user_input
        )
   
    base_digits = find_digits(base_domain)
           
    base_special_characters = find_special_characters(base_domain)
   
    subdomain_digits = find_digits(subdomain)
   
    subdomain_special_characters = find_special_characters(subdomain)
   
    decoded_domain = decode_punycode_domain(base_domain)
   
    unicode_characters = find_non_ascii_characters(decoded_domain)
   
    homoglyphs = find_homoglyphs(decoded_domain)
   
    mixed_script_labels = find_mixed_script_labels(decoded_domain)
   
    punycode_detected = has_punycode(base_domain)

    risk_score, risk_level, risk_reasons = calculate_risk(
        approved_match=approved_match,
        similar_match=similar_match,
        base_digits=base_digits,
        base_special_characters=base_special_characters,
        subdomain_digits=subdomain_digits,
        subdomain_special_characters=subdomain_special_characters,
        non_ascii_characters=unicode_characters,
        homoglyphs=homoglyphs,
        mixed_script_labels=mixed_script_labels,
        punycode_detected=punycode_detected,
        historical_ioc_match=historical_ioc_match,
        threatfox_result=threatfox_result,
    ) 

    report_data = {
        "original_input": user_input,
        "input_type": display_input_type,
        "analysis_mode": analysis_mode,
        "email_address": email_address,
        "hostname": hostname,
        "subdomain": subdomain,
        "base_domain": base_domain,

        "approved_match": approved_match,
        "closest_reference_domain": closest_reference_domain,
        "similarity_score": similarity_score,
        "similar_match": similar_match,

        "historical_ioc_match": historical_ioc_match,
        "historical_ioc_sources": historical_ioc_sources,
        "historical_ioc_details": historical_ioc_details,

        "threatfox_result": threatfox_result,
        "google_safe_browsing_result": (google_safe_browsing_result),
        "phishtank_result": (phishtank_result),

        "base_digits": base_digits,
        "base_special_characters": base_special_characters,

        "subdomain_digits": subdomain_digits,
        "subdomain_special_characters": subdomain_special_characters,

        "punycode_detected": punycode_detected,
        "decoded_domain": decoded_domain,
        "unicode_characters": unicode_characters,
        "homoglyphs": homoglyphs,
        "mixed_script_labels": mixed_script_labels,

        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
    }

    report = generate_report(report_data)

    print()
    print(report)
           
if __name__ == "__main__":
    main()