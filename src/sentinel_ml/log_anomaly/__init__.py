"""Log anomaly detection following r87-e/ais-grupp-logganomali conventions.

Two complementary detectors:
- detector.py      — IsolationForest on structured Wazuh time-window features
- tfidf_detector.py — TF-IDF + IsolationForest on raw log text lines

Supporting modules: generate_data, train, alert_manager, response_playbook,
summarize, attack.
"""
