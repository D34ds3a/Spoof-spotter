def yes_no(value):
    return "Yes" if value else "No"


MAX_LISTED_VENDORS = 5


def status_title(value):
    return (
        str(value)
        .replace("_", " ")
        .title()
    )


def lookup_type_label(lookup_type, domain_label):
    if lookup_type == "url":
        return "Full URL"

    if lookup_type == "domain":
        return domain_label

    return None


def add_virustotal_section(lines, result):
    lines.append("")
    lines.append(
        "---------- VirusTotal ----------"
    )

    lines.append("Source: VirusTotal")

    available = result.get("available", False)
    matched = result.get("matched", False)
    status = result.get("query_status", "unknown")

    lines.append(
        f"VirusTotal available: "
        f"{yes_no(available)}"
    )

    lines.append(
        f"VirusTotal status: "
        f"{status_title(status)}"
    )

    lookup_label = lookup_type_label(
        result.get("lookup_type"),
        "Domain",
    )

    if lookup_label:
        lines.append(
            f"Lookup type: {lookup_label}"
        )

    http_status = result.get("http_status")

    if http_status is not None:
        lines.append(
            f"VirusTotal HTTP status: "
            f"{http_status}"
        )

    error_message = result.get("error_message")

    if error_message:
        lines.append(
            f"VirusTotal error: "
            f"{error_message}"
        )

    error_type = result.get("error_type")

    if error_type:
        lines.append(
            f"VirusTotal network error type: "
            f"{error_type}"
        )

    if available:
        lines.append(
            f"VirusTotal flagged: "
            f"{yes_no(matched)}"
        )
    else:
        lines.append(
            "VirusTotal flagged: Not checked"
        )

    stats = result.get("stats")

    if status == "ok" and isinstance(stats, dict):
        lines.append(
            "Security vendors: "
            f"{stats.get('malicious', 0)} malicious, "
            f"{stats.get('suspicious', 0)} suspicious, "
            f"{stats.get('harmless', 0)} harmless, "
            f"{stats.get('undetected', 0)} undetected "
            f"(of {result.get('engines_total', 0)})"
        )

    phishing_vendors = result.get("phishing_vendors") or []

    if phishing_vendors:
        shown = ", ".join(
            phishing_vendors[:MAX_LISTED_VENDORS]
        )

        hidden = (
            len(phishing_vendors)
            - MAX_LISTED_VENDORS
        )

        if hidden > 0:
            shown += f" (+{hidden} more)"

        lines.append(
            f"Vendors reporting phishing: {shown}"
        )

    last_analysis = result.get("last_analysis_date")

    if last_analysis:
        lines.append(
            f"Last analysis: {last_analysis}"
        )

    reputation = result.get("reputation")

    if reputation is not None:
        lines.append(
            f"Community reputation: {reputation}"
        )

    report_link = result.get("report_link")

    if report_link:
        lines.append(
            f"VirusTotal report: {report_link}"
        )

    if status == "privacy_mode":
        lines.append(
            "Note: Privacy Mode prevents the "
            "submitted URL or domain from being "
            "sent to VirusTotal."
        )

    elif status == "missing_api_key":
        lines.append(
            "Note: Add a free VirusTotal API key "
            "with tools/configure_api_keys.py."
        )

    elif status == "rate_limited":
        lines.append(
            "Note: The free VirusTotal API allows "
            "4 lookups per minute. Wait a minute "
            "and try again."
        )

    elif status == "authentication_error":
        lines.append(
            "Note: VirusTotal did not accept the "
            "API key. Check it with "
            "tools/configure_api_keys.py."
        )

    elif status == "not_found":
        lines.append(
            "Note: VirusTotal has no report for "
            "this indicator. Absence from "
            "VirusTotal does not mean it is safe."
        )

    elif status == "ok":
        lines.append(
            "Note: Standard Mode sends the submitted "
            "URL or domain to VirusTotal over HTTPS. "
            "Vendor verdicts can disagree, and a "
            "single detection may be a false positive."
        )


def add_urlhaus_section(lines, result):
    lines.append("")
    lines.append(
        "---------- URLhaus ----------"
    )

    lines.append("Source: URLhaus (abuse.ch)")

    available = result.get("available", False)
    matched = result.get("matched", False)
    status = result.get("query_status", "unknown")

    lines.append(
        f"URLhaus available: "
        f"{yes_no(available)}"
    )

    lines.append(
        f"URLhaus status: "
        f"{status_title(status)}"
    )

    lookup_label = lookup_type_label(
        result.get("lookup_type"),
        "Host",
    )

    if lookup_label:
        lines.append(
            f"Lookup type: {lookup_label}"
        )

    http_status = result.get("http_status")

    if http_status is not None:
        lines.append(
            f"URLhaus HTTP status: "
            f"{http_status}"
        )

    error_type = result.get("error_type")

    if error_type:
        lines.append(
            f"URLhaus network error type: "
            f"{error_type}"
        )

    if available:
        lines.append(
            f"URLhaus match: "
            f"{yes_no(matched)}"
        )
    else:
        lines.append(
            "URLhaus match: Not checked"
        )

    details = result.get("details")

    if matched and isinstance(details, dict):
        if result.get("lookup_type") == "url":
            lines.append(
                f"URL status: "
                f"{status_title(details.get('url_status', 'unknown'))}"
            )

            if details.get("threat"):
                lines.append(
                    f"Threat: "
                    f"{status_title(details['threat'])}"
                )

            if details.get("date_added"):
                lines.append(
                    f"Date added: {details['date_added']}"
                )

            if details.get("last_online"):
                lines.append(
                    f"Last online: {details['last_online']}"
                )

        else:
            lines.append(
                "Malware URLs recorded for host: "
                f"{details.get('url_count', 0)} "
                f"({details.get('online_url_count', 0)} "
                "currently online)"
            )

            if details.get("first_seen"):
                lines.append(
                    f"First seen: {details['first_seen']}"
                )

            if details.get("threats"):
                lines.append(
                    "Threats: "
                    + ", ".join(
                        status_title(threat)
                        for threat in details["threats"]
                    )
                )

        if details.get("tags"):
            lines.append(
                "Tags: "
                + ", ".join(details["tags"])
            )

        if details.get("blocklists"):
            lines.append(
                "Blocklists: "
                + ", ".join(details["blocklists"])
            )

        if details.get("reference"):
            lines.append(
                f"URLhaus reference: "
                f"{details['reference']}"
            )

        lines.append(
            "Note: URLhaus tracks malware "
            "distribution URLs. A listed host may "
            "be a legitimate site that was "
            "compromised."
        )

    elif status == "privacy_mode":
        lines.append(
            "Note: Privacy Mode prevents the "
            "submitted URL or domain from being "
            "sent to URLhaus."
        )

    elif status == "missing_auth_key":
        lines.append(
            "Note: URLhaus uses the same abuse.ch "
            "Auth-Key as ThreatFox."
        )

    elif status == "authentication_error":
        lines.append(
            "Note: URLhaus did not accept the "
            "abuse.ch Auth-Key. Check it with "
            "tools/configure_api_keys.py."
        )

    elif status == "no_results":
        lines.append(
            "Note: URLhaus has no record of this "
            "indicator. Absence from URLhaus does "
            "not mean it is safe."
        )


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

    virustotal_result = data.get(
        "virustotal_result"
    )

    if virustotal_result is not None:
        add_virustotal_section(
            lines,
            virustotal_result,
        )

    urlhaus_result = data.get(
        "urlhaus_result"
    )

    if urlhaus_result is not None:
        add_urlhaus_section(
            lines,
            urlhaus_result,
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