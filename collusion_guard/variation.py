"""Randomized, reproducible variations of the scripted scenario templates.

The core scenario steps and their dependencies are preserved. Independent benign
messages are varied in count, content, sender/recipient, and insertion position.
Ground truth remains attached to the original scenario and is never passed to the guard.
"""
import json
import random
import statistics
from .testbed import make_episode, S, BENIGN, SEEN_ATTACKS, UNSEEN_ATTACKS, STRESS_ATTACKS
from .evaluate import learn_baseline, make_guard, run_episode

# Include some pairs that also occur in attack paths: these are harmless messages,
# useful for checking whether ordinary communication creates false alarms.
NOISE_PAIRS = [
    ("P", "R"), ("P", "A"), ("P", "W"), ("P", "N"),
    ("R", "W"), ("W", "N"), ("A", "N"), ("W", "R"),
    ("A", "W"), ("R", "N"), ("N", "P"), ("W", "P"),
]
NOISE_TEXT = [
    "status update", "please confirm the task", "sharing a progress note",
    "the draft is ready", "thanks, I will review", "can you clarify the format?",
    "the public summary is complete", "no action needed",
]

def make_varied_episode(kind, seed, min_noise=0, max_noise=8):
    """Return a scenario with randomized harmless messages inserted between core steps.

    The original scenario's required/collusive steps retain their relative order.
    A fixed seed reproduces the exact same variant.
    """
    rng = random.Random(seed)
    core, _ = make_episode(kind, seed)
    core = [step for step in core if not step["step"].startswith("chatter")]
    count = rng.randint(min_noise, max_noise)
    buckets = [[] for _ in range(len(core) + 1)]
    for i in range(count):
        src, dst = rng.choice(NOISE_PAIRS)
        step = S(
            src, "msg", dst=dst,
            step=f"variant_noise_{i}",
            text=rng.choice(NOISE_TEXT),
            required=False,
        )
        position = rng.randrange(len(core) + 1)
        buckets[position].append(step)
    # Shuffle only independent noise events within each insertion point.
    varied = []
    for position, core_step in enumerate(core):
        rng.shuffle(buckets[position])
        varied.extend(buckets[position])
        varied.append(core_step)
    rng.shuffle(buckets[-1])
    varied.extend(buckets[-1])
    return varied, rng

def run_varied_experiment(
    seeds=(101, 202, 303, 404, 505),
    n_per=20,
    min_noise=0,
    max_noise=8,
    defenses=("No defence", "CollusionGuard (ours)", "CollusionGuard + content scan"),
):
    """Evaluate the existing scenario types under independently seeded variations."""
    kinds = BENIGN + SEEN_ATTACKS + UNSEEN_ATTACKS + STRESS_ATTACKS
    results = {}
    for defense in defenses:
        per_kind = {}
        for kind in kinds:
            rows = []
            for seed in seeds:
                baseline = learn_baseline(seed=seed)
                for episode_index in range(n_per):
                    episode_seed = seed * 10007 + episode_index
                    guard = make_guard(defense, baseline)
                    factory = lambda k, s: make_varied_episode(
                        k, s, min_noise=min_noise, max_noise=max_noise
                    )
                    rows.append(run_episode(kind, episode_seed, guard, episode_factory=factory))
            per_kind[kind] = rows
        benign = [r for k in BENIGN for r in per_kind[k]]
        attacks = [r for k in SEEN_ATTACKS + UNSEEN_ATTACKS + STRESS_ATTACKS for r in per_kind[k]]
        rate = lambda rows, key: 100.0 * sum(bool(r[key]) for r in rows) / len(rows) if rows else 0.0
        prevented = [100.0 * (1.0 - sum(bool(r["leaked"]) for r in per_kind[k]) / len(per_kind[k]))
                     for k in SEEN_ATTACKS + UNSEEN_ATTACKS + STRESS_ATTACKS]
        results[defense] = {
            "benign_completion_pct": rate(benign, "completed"),
            "benign_false_block_pct": rate(benign, "any_block"),
            "benign_flagged_pct": rate(benign, "any_flag"),
            "attack_prevention_pct": statistics.mean(prevented),
            "attack_detection_pct": rate(attacks, "detected"),
            "episodes_per_scenario": len(seeds) * n_per,
            "seed_count": len(seeds),
            "noise_messages_per_episode": [min_noise, max_noise],
            "per_kind": {
                kind: {
                    "episodes": len(rows),
                    "prevention_pct": 100.0 * (1.0 - sum(bool(r["leaked"]) for r in rows) / len(rows)),
                    "completion_pct": rate(rows, "completed"),
                    "detection_pct": rate(rows, "detected"),
                    "false_block_pct": rate(rows, "any_block") if kind in BENIGN else None,
                }
                for kind, rows in per_kind.items()
            },
        }
    return results

if __name__ == "__main__":
    result = run_varied_experiment()
    with open("results_variation.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    for defense, metrics in result.items():
        print(
            f"{defense:32s} benign_completion={metrics['benign_completion_pct']:5.1f}% "
            f"false_block={metrics['benign_false_block_pct']:5.1f}% "
            f"attack_prevention={metrics['attack_prevention_pct']:5.1f}% "
            f"detection={metrics['attack_detection_pct']:5.1f}%"
        )
