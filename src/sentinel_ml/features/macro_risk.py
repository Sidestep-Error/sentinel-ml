"""Deterministic macro-risk rule for Office uploads.

A transparent, rule-based layer next to the metadata classifier and the
hash-bridge: sentinel-upload-api extracts static VBA features (olevba) at
upload time and this module flags clearly dangerous combinations.

Deliberately NOT a trained model: we have no honest training data with
content-level features (binaries are never downloaded, only metadata), so a
rule with citable reasoning beats a model fitted on synthesized columns.
Once real macro-feature rows accumulate in the `uploads` collection, the
upload-classifier can be retrained with these columns appended to its
feature contract.
"""

from __future__ import annotations

from sentinel_ml.data.schemas import MacroAnalysis

# An AutoExec trigger (AutoOpen/Workbook_Open/...) combined with any
# suspicious API keyword (Shell, CreateObject, URLDownloadToFile, ...) is the
# classic macro-malware shape: code that runs on open and reaches outside the
# document. Many suspicious keywords without a trigger is still worth
# flagging — droppers sometimes rely on user-invoked controls instead.
_SUSPICIOUS_ALONE_THRESHOLD = 3


def assess_macro_risk(macro: MacroAnalysis | None) -> tuple[bool, str]:
    """Return (is_risky, reason). Reason is set whenever macros are present."""
    if macro is None or not macro.has_macros:
        return False, ""
    if macro.autoexec_keywords >= 1 and macro.suspicious_keywords >= 1:
        return True, (
            "VBA macro with auto-execution trigger and "
            f"{macro.suspicious_keywords} suspicious keyword(s)"
        )
    if macro.suspicious_keywords >= _SUSPICIOUS_ALONE_THRESHOLD:
        return True, f"VBA macro with {macro.suspicious_keywords} suspicious keywords"
    return False, "VBA macro present without auto-execution or suspicious keywords"
