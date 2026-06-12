from sentinel_ml.adversarial.evasion import mimic_upload_metadata, mimic_uploads
from sentinel_ml.data.schemas import UploadRecord


def _malicious_record() -> UploadRecord:
    return UploadRecord(
        filename="payload.exe",
        content_type="application/x-dosexec",
        sha256="a" * 64,
        size_bytes=2_000_000,
        scan_status="clean",
        decision="rejected",
        risk_score=0,
        scan_engine="clamav",
        scan_detail="No signature matched",
    )


def test_mimic_upload_metadata_changes_only_attacker_controlled_fields():
    original = _malicious_record()

    mimicked = mimic_upload_metadata(original)

    assert mimicked.filename == "quarterly_report.pdf"
    assert mimicked.content_type == "application/pdf"
    assert mimicked.size_bytes == 500_000
    assert mimicked.sha256 == original.sha256
    assert mimicked.scan_status == original.scan_status
    assert mimicked.risk_score == original.risk_score
    assert mimicked.decision == original.decision


def test_mimic_upload_metadata_does_not_mutate_original():
    original = _malicious_record()

    mimic_upload_metadata(original)

    assert original.filename == "payload.exe"
    assert original.content_type == "application/x-dosexec"
    assert original.size_bytes == 2_000_000


def test_mimic_uploads_preserves_order_and_count():
    records = [_malicious_record(), _malicious_record()]

    mimicked = mimic_uploads(records)

    assert len(mimicked) == 2
    assert all(record.filename == "quarterly_report.pdf" for record in mimicked)
