def find_digits(domain):
    digits_found = []

    for character in domain:
        if character.isascii() and character.isdigit():
            digits_found.append(character)

    return digits_found

def find_special_characters(domain):
    special_characters = []

    for character in domain:
        if not character.isalnum() and character != ".":
            special_characters.append(character)

    return special_characters

def has_digits(domain):
    return bool(find_digits(domain))


def has_special_characters(domain):
    return bool(find_special_characters(domain))