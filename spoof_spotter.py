from core.parser import (
    classify_input,
    parse_email,
    parse_domain,
    validate_email,
    validate_domain,
    extract_domain_parts,
)

def main():
    print("=========================")
    print("      SPOOF SPOTTER")
    print("=========================")

    user_input = input("\nEnter an email or website: ").strip()

    input_type = classify_input(user_input)

    if input_type == "empty":
        print("\nError: No input was provided.")

    elif input_type == "email":
        if not validate_email(user_input):
            print("\nError: Invalid email address.")
            return

        address, domain = parse_email(user_input)

        print("\nInput type: EMAIL")
        print(f"Email address: {address}")
        print(f"Domain: {domain}")

    elif input_type == "domain":
        if not validate_domain(user_input):
            print("\nError: Invalid domain or website.")
            return

        domain = parse_domain(user_input)
        subdomain, base_domain = extract_domain_parts(user_input)

        print("\nInput type: DOMAIN/WEBSITE")
        print(f"Hostname: {domain}")
        print(f"Subdomain: {subdomain if subdomain else 'None'}")
        print(f"Base domain: {base_domain}")
        
if __name__ == "__main__":
    main()