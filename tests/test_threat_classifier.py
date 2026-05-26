"""Smoke test — train on a tiny synthetic dataset and assert basic behaviour."""

from sentinel_ml.models import threat_classifier


def test_train_and_predict_smoke():
    texts = [
        "ransomware encrypted files and demanded payment",
        "ransomware variant spreading via SMB",
        "phishing email impersonating a bank",
        "phishing campaign harvesting credentials",
        "ddos flood saturating uplink",
        "ddos botnet hitting public endpoints",
    ]
    labels = ["ransomware", "ransomware", "phishing", "phishing", "ddos", "ddos"]

    pipe = threat_classifier.train(texts, labels)
    pred = pipe.predict(["new ransomware sample seen in the wild"])
    assert pred[0] in {"ransomware", "phishing", "ddos"}


def test_pipeline_predict_proba_shape():
    texts = ["phishing email", "ransomware payload", "ddos flood", "phishing campaign"]
    labels = ["phishing", "ransomware", "ddos", "phishing"]
    pipe = threat_classifier.train(texts, labels)
    proba = pipe.predict_proba(["random text"])
    assert proba.shape == (1, 3)
