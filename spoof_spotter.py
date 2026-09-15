from core.parser import classify_input, parse_email, parse_domain

def main():
    print("=========================")
    print("      SPOOF SPOTTER")
    print("=========================")

    user_input = input("\nEnter an email or website: ").strip()

    input_type = classify_input(user_input)

    if input_type == "empty":
        print("\nError: No input was provided.")

    elif input_type == "email":
        address, domain = parse_email(user_input)

        print("\nInput type: EMAIL")
        print(f"Email address: {address}")
        print(f"Domain: {domain}")

    elif input_type == "domain":
        domain = parse_domain(user_input)

        if domain:
            print("\nInput type: DOMAIN/WEBSITE")
            print(f"Domain: {domain}")
        else:
            print("\nError: The domain could not be parsed.")

if __name__ == "__main__":
    main()