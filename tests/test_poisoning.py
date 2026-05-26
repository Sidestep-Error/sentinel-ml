from sentinel_ml.adversarial.poisoning import poison_labels


def test_poison_ratio_zero_is_noop():
    texts = ["a", "b", "c", "d"]
    labels = ["x", "y", "x", "y"]
    result = poison_labels(texts, labels, ratio=0.0, classes=["x", "y"])
    assert result.labels == labels
    assert result.n_poisoned == 0


def test_poison_flips_correct_count():
    texts = list("abcdefghij")
    labels = ["x"] * 10
    result = poison_labels(texts, labels, ratio=0.5, classes=["x", "y"])
    assert result.n_poisoned == 5
    # Five labels must have been changed (to "y", since "x" is excluded)
    assert sum(1 for v in result.labels if v == "y") == 5


def test_poison_invalid_ratio_raises():
    import pytest

    with pytest.raises(ValueError):
        poison_labels(["a"], ["x"], ratio=1.5, classes=["x", "y"])
