from pathlib import Path

from scripts.run_adversarial_experiments import _write_poisoning_svg


def test_write_poisoning_svg_contains_all_ratios_and_scores(tmp_path: Path):
    results = [
        {"ratio": 0.0, "f1_macro": 0.963},
        {"ratio": 0.05, "f1_macro": 0.930},
        {"ratio": 0.10, "f1_macro": 0.866},
        {"ratio": 0.20, "f1_macro": 0.807},
    ]
    output = tmp_path / "poisoning.svg"

    _write_poisoning_svg(results, output)

    svg = output.read_text(encoding="utf-8")
    assert svg.startswith("<svg")
    assert "0%" in svg
    assert "5%" in svg
    assert "10%" in svg
    assert "20%" in svg
    assert "0.963" in svg
    assert "0.807" in svg
