def yes_no(value):
    return "Yes" if value else "No"


def generate_report(data):
    lines = []

    lines.append("============== SPOOF SPOTTER REPORT ==============")
    lines.append(f"Original input: {data['original_input']}")
    lines.append(f"Input type: {data['input_type']}")

    analysis_mode = data.get(
        "analysis_mode",
        "standard",
    )

    lines.append(f"Analysis mode: "f"{analysis_mode.title()}")

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


    lines.append("")
    lines.append(
        "---------- Local Domain Analysis ----------"
    )

    if not data["approved_match"]:
        lines.append(
            f"Closest reference domain: "
            f"{data['closest_reference_domain']}"
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
        f"Subdomain: "
        f"{subdomain if subdomain else 'None'}"
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
            f"Decoded domain: "
            f"{data['decoded_domain']}"
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

        lines.append(f"ThreatFox status: {status_text}")

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

    google_result = data.get(
        "google_safe_browsing_result"
    )

    if google_result is not None:
        lines.append("")
        lines.append(
            "---------- Google Safe Browsing ----------"
        )

        google_available = (
            google_result.get(
                "available",
                False,
            )
        )

        google_matched = (
            google_result.get(
                "matched",
                False,
            )
        )

        google_status = (
            google_result.get(
                "query_status",
                "unknown",
            )
        )

        status_text = (
            str(google_status)
            .replace("_", " ")
            .title()
        )

        lines.append(
            "Source: Google Safe Browsing"
        )

        lines.append(
            f"Google available: "
            f"{yes_no(google_available)}"
        )

        lines.append(
            f"Google status: "
            f"{status_text}"
        )

        http_status = (
            google_result.get(
                "http_status"
            )
        )

        if http_status is not None:
            lines.append(
                f"Google HTTP status: "
                f"{http_status}"
            )

        error_message = (
            google_result.get(
                "error_message"
            )
        )

        if error_message:
            lines.append(
                f"Google error: "
                f"{error_message}"
            )

        error_type = (
            google_result.get(
                "error_type"
            )
        )

        if error_type:
            lines.append(
                f"Google network error type: "
                f"{error_type}"
            )

        if google_available:
            lines.append(
                f"Google full-hash match: "
                f"{yes_no(google_matched)}"
            )
        else:
            lines.append(
                "Google full-hash match: "
                "Not checked"
            )

        cache_status = (
            google_result.get(
                "cache_status"
            )
        )

        if cache_status:
            cache_text = (
                str(cache_status)
                .replace("_", " ")
                .title()
            )

            lines.append(
                f"Google cache status: "
                f"{cache_text}"
            )

        network_request = (
            google_result.get(
                "network_request_made"
            )
        )

        if network_request is not None:
            lines.append(
                f"Google network request made: "
                f"{yes_no(network_request)}"
            )

        cache_duration = (
            google_result.get(
                "cache_duration"
            )
        )

        if cache_duration:
            lines.append(
                f"Google cache duration: "
                f"{cache_duration}"
            )

        if google_matched:
            seen_details = set()

            for match in google_result.get(
                "matches",
                [],
            ):
                for detail in match.get(
                    "details",
                    [],
                ):
                    threat_type = (
                        detail.get(
                            "threatType",
                            "Unknown",
                        )
                    )

                    attributes = tuple(
                        detail.get(
                            "attributes",
                            [],
                        )
                    )

                    detail_key = (
                        threat_type,
                        attributes,
                    )

                    if (
                        detail_key
                        in seen_details
                    ):
                        continue

                    seen_details.add(
                        detail_key
                    )

                    threat_text = (
                        threat_type
                        .replace("_", " ")
                        .title()
                    )

                    lines.append(
                        f"Google threat type: "
                        f"{threat_text}"
                    )

                    if attributes:
                        attribute_text = (
                            ", ".join(
                                attributes
                            )
                        )

                        lines.append(
                            "Google threat attributes: "
                            f"{attribute_text}"
                        )

        lines.append(
            "Note: Google Safe Browsing "
            "lookups use locally generated "
            "hash prefixes rather than sending "
            "the submitted URL directly."
        )

    phishtank_result = data.get(
        "phishtank_result"
    )

    if phishtank_result is not None:
        lines.append("")
        lines.append(
            "---------- Phishing Intelligence ----------"
        )

        lines.append(
            "Source: PhishTank"
        )

        available = (
            phishtank_result.get(
                "available",
                False,
            )
        )

        matched = (
            phishtank_result.get(
                "matched",
                False,
            )
        )

        listed = (
            phishtank_result.get(
                "listed",
                False,
            )
        )

        status = (
            phishtank_result.get(
                "query_status",
                "unknown",
            )
        )

        status_text = (
            str(status)
            .replace("_", " ")
            .title()
        )

        lines.append(
            f"PhishTank available: "
            f"{yes_no(available)}"
        )

        lines.append(
            f"PhishTank status: "
            f"{status_text}"
        )

        if available:
            lines.append(
                f"URL in database: "
                f"{yes_no(listed)}"
            )

            lines.append(
                f"Verified active phish: "
                f"{yes_no(matched)}"
            )
        else:
            lines.append(
                "PhishTank match: "
                "Not checked"
            )

        finding = (
            phishtank_result.get(
                "result"
            )
        )

        if finding:
            verified = finding.get(
                "verified",
                False,
            )

            valid = finding.get(
                "valid",
                False,
            )

            lines.append(
                f"Verified: "
                f"{yes_no(verified)}"
            )

            lines.append(
                f"Currently valid: "
                f"{yes_no(valid)}"
            )

            phish_id = finding.get(
                "phish_id"
            )

            if phish_id is not None:
                lines.append(
                    f"PhishTank ID: "
                    f"{phish_id}"
                )

            verified_at = finding.get(
                "verified_at"
            )

            if verified_at:
                lines.append(
                    f"Verified at: "
                    f"{verified_at}"
                )

            submitted_at = finding.get(
                "submitted_at"
            )

            if submitted_at:
                lines.append(
                    f"Submitted at: "
                    f"{submitted_at}"
                )

        if status == "privacy_mode":
            lines.append(
                "Note: Privacy Mode prevents "
                "the submitted URL from being "
                "sent to PhishTank."
            )

        elif status == (
            "not_applicable_email"
        ):
            lines.append(
                "Note: PhishTank checks URLs, "
                "not standalone email addresses."
            )

        elif status == (
            "full_url_required"
        ):
            lines.append(
                "Note: PhishTank lookup requires "
                "a complete URL rather than a "
                "bare domain."
            )

        elif available:
            lines.append(
                "Note: Standard Mode sends the "
                "submitted URL to PhishTank over "
                "HTTPS for database lookup."
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