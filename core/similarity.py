from difflib import SequenceMatcher


DEFAULT_SIMILARITY_THRESHOLD = 0.80


def calculate_similarity(domain_one, domain_two):
    domain_one = domain_one.lower()
    domain_two = domain_two.lower()

    return SequenceMatcher(
        None,
        domain_one,
        domain_two,
    ).ratio()


def find_closest_domain(base_domain, reference_domains):
    closest_domain = None
    highest_score = 0.0

    for reference_domain in reference_domains:
        score = calculate_similarity(
            base_domain,
            reference_domain,
        )

        if score > highest_score:
            highest_score = score
            closest_domain = reference_domain

    return closest_domain, highest_score


def is_similar_score(
    similarity_score,
    threshold=DEFAULT_SIMILARITY_THRESHOLD,
):
    return similarity_score >= threshold