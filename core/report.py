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
    lines.append(
        f"Approved domain: {yes_no(data['approved_match'])}"
    )

    lines.append(
        f"Historical IOC match: "
        f"{yes_no(data['historical_ioc_match'])}"
    )

    if data["historical_ioc_match"]:
        lines.append("Historical threat intelligence:")

        for finding in data["historical_ioc_details"]:
            lines.append(
                f"- Source: {finding['source']}"
            )
            lines.append(
                f"  Domain creation date: "
                f"{finding['creation_date']}"
            )
            lines.append(
                f"  IOC status: "
                f"{finding['status'].title()}"
            )

        lines.append(
            "Note: Historical IOC matches do not by themselves "
            "establish current malicious activity."
        )

    threatfox_result = data.get("threatfox_result")

    if threatfox_result is not None:
        lines.append("")
        lines.append(
            "---------- Live Threat Intelligence ----------"
        )

        lines.append("Source: ThreatFox")

        threatfox_available = threatfox_result.get(
            "available",
            False,
        )

        threatfox_matched = threatfox_result.get(
            "matched",
            False,
        )

        query_status = threatfox_result.get(
            "query_status",
            "unknown",
        )

        lines.append(
            f"ThreatFox available: "
            f"{yes_no(threatfox_available)}"
        )

        status_text = (
            str(query_status)
            .replace("_", " ")
            .title()
        )

        lines.append(
            f"ThreatFox status: {status_text}"
        )

        if threatfox_available:
            lines.append(
                f"ThreatFox match: "
                f"{yes_no(threatfox_matched)}"
            )
        else:
            lines.append(
                "ThreatFox match: Not checked"
            )

        if threatfox_matched:
            for finding in threatfox_result.get(
                "results",
                [],
            ):
                lines.append(f"IOC: {finding.get('ioc', 'Unknown')}")

                ioc_type = (finding.get("ioc_type") or "Unknown")

                lines.append(f"IOC type: {ioc_type.title()}")

                threat_type = (finding.get("threat_type") or "Unknown")

                threat_type = (
                    threat_type
                    .replace("_", " ")
                    .title()
                )

                lines.append(f"Threat type: {threat_type}")

                description = finding.get("threat_description")

                if description:
                    lines.append(f"Threat description: {description}")

                malware = (
                    finding.get("malware") or "Unknown")

                lines.append(f"Malware: {malware}")

                confidence = finding.get("confidence")

                if confidence is not None:
                    lines.append(f"Confidence: {confidence}")

                first_seen = (finding.get("first_seen") or "Unknown")

                lines.append(f"First seen: {first_seen}")

                last_seen = (finding.get("last_seen") or "Not provided")

                lines.append(f"Last seen: {last_seen}")

                compromised = finding.get("is_compromised")

                if compromised is True:
                    compromised_text = "Yes"
                elif compromised is False:
                    compromised_text = "No"
                else:
                    compromised_text = "Unknown"

                lines.append(f"Compromised host: "f"{compromised_text}")

            lines.append(
                "Note: A ThreatFox match is a threat-"
                "intelligence indicator and does not by "
                "itself establish the current intent or "
                "ownership of a domain."
            )

            lines.append(
                "A compromised host may belong to an "
                "otherwise legitimate service."
            )

    if not data["approved_match"]:
        lines.append(
            f"Closest approved domain: "
            f"{data['closest_domain']}"
        )
        lines.append(
            f"Similarity score: "
            f"{data['similarity_score'] * 100:.1f}%"
        )
        lines.append(
            f"Similar-looking domain: "
            f"{yes_no(data['similar_match'])}"
        )

    lines.append(
        f"Base domain numbers detected: "
        f"{yes_no(data['base_digits'])}"
    )

    if data["base_digits"]:
        lines.append(
            f"Base domain numbers found: "
            f"{', '.join(data['base_digits'])}"
        )

    lines.append(
        f"Base domain special characters detected: "
        f"{yes_no(data['base_special_characters'])}"
    )

    if data["base_special_characters"]:
        lines.append(
            f"Base domain special characters found: "
            f"{', '.join(data['base_special_characters'])}"
        )

    subdomain = data["subdomain"]

    lines.append(
        f"Subdomain: {subdomain if subdomain else 'None'}"
    )

    if subdomain:
        lines.append(
            f"Subdomain numbers detected: "
            f"{yes_no(data['subdomain_digits'])}"
        )

        if data["subdomain_digits"]:
            lines.append(
                f"Subdomain numbers found: "
                f"{', '.join(data['subdomain_digits'])}"
            )

        lines.append(
            f"Subdomain special characters detected: "
            f"{yes_no(data['subdomain_special_characters'])}"
        )

        if data["subdomain_special_characters"]:
            lines.append(
                f"Subdomain special characters found: "
                f"{', '.join(data['subdomain_special_characters'])}"
            )

    lines.append(
        f"Punycode detected: "
        f"{yes_no(data['punycode_detected'])}"
    )

    if data["punycode_detected"]:
        lines.append(
            f"Decoded domain: {data['decoded_domain']}"
        )

    lines.append(
        f"Non-ASCII characters detected: "
        f"{yes_no(data['unicode_characters'])}"
    )

    lines.append(
        f"Potential homoglyphs detected: "
        f"{yes_no(data['homoglyphs'])}"
    )

    for (
        character,
        looks_like,
        codepoint,
        unicode_name,
    ) in data["homoglyphs"]:
        lines.append(
            f"Potential homoglyph: "
            f"{character} -> {looks_like} "
            f"({codepoint}, {unicode_name})"
        )

    lines.append(
        f"Mixed-script labels detected: "
        f"{yes_no(data['mixed_script_labels'])}"
    )

    if data["mixed_script_labels"]:
        lines.append(
            f"Mixed-script labels found: "
            f"{', '.join(data['mixed_script_labels'])}"
        )

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

    lines.append(
        "=================================================="
    )

    return "\n".join(lines)