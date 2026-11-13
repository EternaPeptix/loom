"""Regression cases for censoring/unknown-usage and pairing, not synthetic performance claims."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("security_eval", Path(__file__).with_name("security-eval.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(workflow, **overrides):
    value = dict(task_id="held-out-fixture", repeat=0, workflow=workflow, settings_hash="same",
                 elapsed_s=10, censored=False, verified_finish=True, oracle_accepted=True,
                 controls_passed=True, usage_complete=True, prompt_tokens=100, completion_tokens=20,
                 cached_tokens=50)
    value.update(overrides)
    return value


class EvaluationTests(unittest.TestCase):
    def test_censored_failures_stay_in_denominator_and_never_become_latency(self):
        result = module.analyze([row("core"), row("ctf", censored=True, elapsed_s=420)])
        self.assertEqual(result["workflows"]["ctf"]["episodes"], 1)
        self.assertEqual(result["workflows"]["ctf"]["verified_successes"], 0)
        self.assertIsNone(result["pairs"][0]["latency_ratio"])

    def test_unknown_usage_stays_unknown_despite_partial_counts(self):
        result = module.analyze([row("core"), row("ctf", usage_complete=False, prompt_tokens=None,
                                                    completion_tokens=None, known_completion_tokens=7)])
        self.assertIsNone(result["pairs"][0]["total_token_ratio"])
        self.assertFalse(result["workflows"]["ctf"]["usage_totals_exact"])
        self.assertEqual(result["workflows"]["ctf"]["known_completion_lower_bound"]["reported"], 7)

    def test_mismatched_and_missing_arms_report_pairing_errors(self):
        result = module.analyze([row("core"), row("ctf", settings_hash="different"), row("core", repeat=1)])
        self.assertEqual(len(result["pairing_errors"]), 2)
        self.assertFalse(result["pairs"])
        with self.assertRaises(ValueError):
            module.analyze([row("core"), row("core")])

    def test_model_verdict_does_not_replace_oracle_and_complete_ratios_are_exact(self):
        result = module.analyze([row("core"), row("ctf", oracle_accepted=False, prompt_tokens=50, completion_tokens=10, cached_tokens=25)])
        self.assertEqual(result["workflows"]["ctf"]["verified_successes"], 0)
        self.assertEqual(result["pairs"][0]["total_token_ratio"], 0.5)
        self.assertIsNone(result["pairs"][0]["latency_ratio"])


if __name__ == "__main__":
    unittest.main()
