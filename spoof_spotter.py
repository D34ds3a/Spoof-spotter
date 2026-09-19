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

def main():
    print("=========================")
    print("      SPOOF SPOTTER")
    print("=========================")

    user_input = input("\nEnter an email or website: ").strip()

    input_type = classify_input(user_input)

    approved_domains = load_approved_domains()

    if input_type == "empty":
        print("\nError: No input was provided.")

    elif input_type == "email":
        if not validate_email(user_input):
            print("\nError: Invalid email address.")
            return

        address, domain = parse_email(user_input)

        subdomain, base_domain = extract_domain_parts(domain)

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

        print("\nInput type: EMAIL")
        print(f"Email address: {address}")
        print(f"Domain: {domain}")
        print(f"Base domain: {base_domain}")
        print(f"Subdomain: {subdomain if subdomain else 'None'}")
        print(
            f"Approved domain: {'Yes' if approved_match else 'No'}"
        )
        if not approved_match:
            print(f"Closest approved domain: {closest_domain}")
            print(
                f"Similarity score: {similarity_score * 100:.1f}%"
            )
            print(
                f"Similar-looking domain: "
                f"{'Yes' if similar_match else 'No'}"
            )

    elif input_type == "domain":
        if not validate_domain(user_input):
            print("\nError: Invalid domain or website.")
            return

        domain = parse_domain(user_input)
        subdomain, base_domain = extract_domain_parts(user_input)

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

        print("\nInput type: DOMAIN/WEBSITE")
        print(f"Hostname: {domain}")
        print(f"Subdomain: {subdomain if subdomain else 'None'}")
        print(f"Base domain: {base_domain}")
        print(
            f"Approved domain: {'Yes' if approved_match else 'No'}"
        )
        if not approved_match:
            print(f"Closest approved domain: {closest_domain}")
            print(
                f"Similarity score: {similarity_score * 100:.1f}%"
            )
            print(
                f"Similar-looking domain: "
                f"{'Yes' if similar_match else 'No'}"
            )
        
if __name__ == "__main__":
    main()