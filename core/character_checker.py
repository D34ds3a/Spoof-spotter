import unicodedata

HOMOGLYPH_MAP = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0458": "j",
    "\u03bf": "o",
    "\u03c1": "p",
}

def find_digits(domain):
    digits_found = []

    for character in domain:
        if character.isascii() and character.isdigit():
            digits_found.append(character)

    return digits_found

def find_special_characters(domain):
    special_characters = []

    for character in domain:
        if not character.isalnum() and character not in ".-":
            special_characters.append(character)

    return special_characters

def has_digits(domain):
    return bool(find_digits(domain))


def has_special_characters(domain):
    return bool(find_special_characters(domain))

def find_non_ascii_characters(text):
    non_ascii = []

    for character in text:
        if not character.isascii():
            non_ascii.append(character)

    return non_ascii

def find_homoglyphs(text):
    findings = []

    for character in text:
        if character in HOMOGLYPH_MAP:
            findings.append(
                (
                    character,
                    HOMOGLYPH_MAP[character],
                    f"U+{ord(character):04X}",
                    unicodedata.name(character, "UNKNOWN"),
                )
            )

    return findings

def find_mixed_script_labels(domain):
    mixed_labels = []

    for label in domain.split("."):
        scripts = set()

        for character in label:
            if not character.isalpha():
                continue

            name = unicodedata.name(character, "")

            if "LATIN" in name:
                scripts.add("LATIN")

            elif "CYRILLIC" in name:
                scripts.add("CYRILLIC")

            elif "GREEK" in name:
                scripts.add("GREEK")

        if len(scripts) > 1:
            mixed_labels.append(label)

    return mixed_labels

def has_punycode(domain):
    for label in domain.split("."):
        if label.lower().startswith("xn--"):
            return True

    return False

def decode_punycode_domain(domain):
    decoded_labels = []

    for label in domain.split("."):
        if label.lower().startswith("xn--"):
            try:
                decoded_label = label.encode("ascii").decode("idna")
                decoded_labels.append(decoded_label)

            except UnicodeError:
                decoded_labels.append(label)

        else:
            decoded_labels.append(label)

    return ".".join(decoded_labels)