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
    is_similar_domain,
)

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
 


def main():
    print("=========================")
    print("      SPOOF SPOTTER")
    print("=========================")

    user_input = input("\nEnter an email or website: ").strip()

    input_type = classify_input(user_input)

    approved_domains = load_approved_domains()

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
   
    closest_domain, similarity_score = find_closest_domain(
        base_domain,
        approved_domains
    )
           
    similar_match = is_similar_domain(
        base_domain,
        approved_domains
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
    ) 

    report_data = {
        "original_input": user_input,
        "input_type": display_input_type,
        "email_address": email_address,
        "hostname": hostname,
        "subdomain": subdomain,
        "base_domain": base_domain,

        "approved_match": approved_match,
        "closest_domain": closest_domain,
        "similarity_score": similarity_score,
        "similar_match": similar_match,

        "historical_ioc_match": historical_ioc_match,
        "historical_ioc_sources": historical_ioc_sources,
        "historical_ioc_details": historical_ioc_details,

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