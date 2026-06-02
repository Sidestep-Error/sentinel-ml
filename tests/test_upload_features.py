import numpy as np

from sentinel_ml.features.upload_meta import FEATURE_COLUMNS, build_feature_matrix


def test_feature_matrix_shape(sample_upload_record):
    matrix, cols = build_feature_matrix([sample_upload_record])
    assert matrix.shape == (1, len(FEATURE_COLUMNS))
    assert cols == FEATURE_COLUMNS


def test_feature_matrix_empty():
    matrix, cols = build_feature_matrix([])
    assert matrix.shape == (0, len(FEATURE_COLUMNS))
    assert cols == FEATURE_COLUMNS


def test_clean_upload_sets_scan_status_clean(sample_upload_record):
    matrix, cols = build_feature_matrix([sample_upload_record])
    idx = cols.index("scan_status_clean")
    assert matrix[0, idx] == 1.0
    assert matrix[0, cols.index("scan_status_malicious")] == 0.0


def test_features_are_finite(sample_upload_record):
    matrix, _ = build_feature_matrix([sample_upload_record])
    assert np.all(np.isfinite(matrix))


def test_size_bytes_none_yields_zero_log_feature(sample_upload_record):
    """Legacy documents without size_bytes must not crash feature extraction."""
    record = sample_upload_record.model_copy(update={"size_bytes": None})
    matrix, cols = build_feature_matrix([record])
    idx = cols.index("size_bytes_log")
    assert matrix[0, idx] == 0.0
    assert np.all(np.isfinite(matrix))
