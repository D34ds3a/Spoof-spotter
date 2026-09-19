from difflib import SequenceMatcher

def calculate_similarity(domain_one, domain_two):
    domain_one = domain_one.lower()
    domain_two = domain_two.lower()

    return SequenceMatcher(
        None,
        domain_one,
        domain_two
    ).ratio()

def find_closest_domain(base_domain, approved_domains):
    closest_domain = None
    highest_score = 0.0

    for approved_domain in approved_domains:
        score = calculate_similarity(
            base_domain,
            approved_domain
        )

        if score > highest_score:
            highest_score = score
            closest_domain = approved_domain

    return closest_domain, highest_score

def is_similar_domain(
    base_domain,
    approved_domains,
    threshold=0.80
):
    closest_domain, score = find_closest_domain(
        base_domain,
        approved_domains
    )

    return score >= threshold