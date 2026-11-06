"""Small aggregation helpers shared by the experiment scripts."""
import csv
import statistics as stats
from typing import List, Sequence


def win_rate(outcomes: Sequence[bool]) -> float:
    if not outcomes:
        return 0.0
    return sum(1 for o in outcomes if o) / len(outcomes)


def mean_std(values: Sequence[float]):
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return stats.mean(values), stats.stdev(values)


def mean_ci(values: Sequence[float]):
    """Mean and 95% half-width (normal approximation, fine for the 20 seeds used here)."""
    m, sd = mean_std(values)
    n = len(values)
    return m, (1.96 * sd / n ** 0.5 if n > 1 else 0.0)


def write_csv(path: str, rows: List[dict], fieldnames: List[str] = None):
    if not rows:
        return
    fieldnames = fieldnames or list(rows[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {len(rows)} rows -> {path}")
