from pathlib import Path
import statistics
import sys
import time


PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from core.reference_domains import load_reference_domains
from core.similarity import (
    find_closest_domain,
    is_similar_score,
)


TEST_DOMAIN = "micros0ft.com"
RUNS = 5


def main():
    reference_domains = load_reference_domains()

    print("============== SIMILARITY BENCHMARK ==============")
    print(f"Test domain: {TEST_DOMAIN}")
    print(f"Reference domains: {len(reference_domains):,}")
    print(f"Runs: {RUNS}")
    print()

    timings = []

    for run_number in range(1, RUNS + 1):
        start_time = time.perf_counter()

        closest_domain, similarity_score = find_closest_domain(
            TEST_DOMAIN,
            reference_domains,
        )

        similar_match = is_similar_score(similarity_score)
        end_time = time.perf_counter()

        elapsed_time = end_time - start_time
        timings.append(elapsed_time)

        print(
            f"Run {run_number}: "
            f"{elapsed_time:.4f} seconds"
        )

    print()
    print(f"Closest reference domain: {closest_domain}")
    print(
        f"Similarity score: "
        f"{similarity_score * 100:.1f}%"
    )
    print(
        f"Similar-looking domain: "
        f"{'Yes' if similar_match else 'No'}"
    )

    print()
    print("--------------- RESULTS ---------------")
    print(
        f"Average: {statistics.mean(timings):.4f} seconds"
    )
    print(
        f"Fastest: {min(timings):.4f} seconds"
    )
    print(
        f"Slowest: {max(timings):.4f} seconds"
    )


if __name__ == "__main__":
    main()