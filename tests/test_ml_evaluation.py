import unittest

from evaluate_anomaly_detection import metrics


class EvaluationMetricsTests(unittest.TestCase):
    def test_perfect_predictions(self):
        result = metrics([0, 1, 0, 1], [0, 1, 0, 1])
        self.assertEqual(result["confusion_matrix"], {"tn": 2, "fp": 0, "fn": 0, "tp": 2})
        self.assertEqual(result["precision"], 1.0)
        self.assertEqual(result["recall"], 1.0)
        self.assertEqual(result["f1"], 1.0)
        self.assertEqual(result["accuracy"], 1.0)

    def test_false_positive_and_false_negative_are_counted(self):
        result = metrics([0, 1], [1, 0])
        self.assertEqual(result["confusion_matrix"], {"tn": 0, "fp": 1, "fn": 1, "tp": 0})
        self.assertEqual(result["precision"], 0.0)
        self.assertEqual(result["recall"], 0.0)
        self.assertEqual(result["f1"], 0.0)

    def test_empty_input_is_safe(self):
        result = metrics([], [])
        self.assertEqual(result["accuracy"], 0.0)
        self.assertEqual(result["confusion_matrix"], {"tn": 0, "fp": 0, "fn": 0, "tp": 0})


if __name__ == "__main__":
    unittest.main()
