def yes_no(value):
    return "Yes" if value else "No"

def generate_report(data):
    lines = []

    lines.append("============== SPOOF SPOTTER REPORT ==============")
    lines.append(f"Original input: {data['original_input']}")
    lines.append(f"Input type: {data['input_type']}")

    if data["input_type"] == "EMAIL":
        lines.append(f"Email address: {data['email_address']}")
        lines.append(f"Domain: {data['hostname']}")
    else:
        lines.append(f"Hostname: {data['hostname']}")

    lines.append(f"Base domain: {data['base_domain']}")
    lines.append(f"Approved domain: {yes_no(data['approved_match'])}")

    if not data["approved_match"]:
        lines.append(f"Closest approved domain: {data['closest_domain']}")

        lines.append(f"Similarity score: " f"{data['similarity_score'] * 100:.1f}%")

        lines.append(f"Similar-looking domain: " f"{yes_no(data['similar_match'])}")

    lines.append("Base domain numbers detected: " f"{yes_no(data['base_digits'])}")

    if data["base_digits"]:
        lines.append( "Base domain numbers found: " f"{', '.join(data['base_digits'])}")

    lines.append("Base domain special characters detected: " f"{yes_no(data['base_special_characters'])}")

    if data["base_special_characters"]:
        lines.append("Base domain special characters found: " f"{', '.join(data['base_special_characters'])}")

    subdomain = data["subdomain"]

    lines.append(f"Subdomain: {subdomain if subdomain else 'None'}")

    if subdomain:
        lines.append("Subdomain numbers detected: " f"{yes_no(data['subdomain_digits'])}")

        if data["subdomain_digits"]:
            lines.append("Subdomain numbers found: " f"{', '.join(data['subdomain_digits'])}")

        lines.append(
            "Subdomain special characters detected: " f"{yes_no(data['subdomain_special_characters'])}")

        if data["subdomain_special_characters"]:
            lines.append("Subdomain special characters found: " f"{', '.join(data['subdomain_special_characters'])}")

    lines.append(f"Punycode detected: " f"{yes_no(data['punycode_detected'])}")

    if data["punycode_detected"]:
        lines.append(f"Decoded domain: {data['decoded_domain']}")

    lines.append("Non-ASCII characters detected: "f"{yes_no(data['unicode_characters'])}")
    
    lines.append("Potential homoglyphs detected: "f"{yes_no(data['homoglyphs'])}")

    for (
        character,
        looks_like,
        codepoint,
        unicode_name,
    ) in data["homoglyphs"]:
        lines.append(f"Potential homoglyph: " f"{character} -> {looks_like} " f"({codepoint}, {unicode_name})")

    lines.append("Mixed-script labels detected: " f"{yes_no(data['mixed_script_labels'])}")

    if data["mixed_script_labels"]:
        lines.append("Mixed-script labels found: " f"{', '.join(data['mixed_script_labels'])}")


    lines.append("")
    lines.append("---------- Risk Assessment ----------")

    lines.append(f"Risk score: {data['risk_score']}/100")

    lines.append(f"Risk level: {data['risk_level']}")

    if data["risk_reasons"]:
        lines.append("Indicators:")

        for reason in data["risk_reasons"]:
            lines.append(f"- {reason}")

    else:
        lines.append("Indicators: None")

    lines.append("==================================================")

    return "\n".join(lines)