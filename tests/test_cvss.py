import pytest

from astranyx.scoring.cvss import CVSSVectorError, assess


@pytest.mark.parametrize(
    "vector, expected_score, expected_severity",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8, "High"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N", 4.2, "Medium"),
        ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0, "None"),
    ],
)
def test_scores_cvss_v31_base_vectors(vector, expected_score, expected_severity):
    result = assess(vector)

    assert result.score == expected_score
    assert result.severity == expected_severity


def test_canonicalizes_metric_order_and_case():
    result = assess("cvss:3.1/a:h/i:h/c:h/s:u/ui:n/pr:n/ac:l/av:n")

    assert result.vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.parametrize(
    "vector, message",
    [
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "only CVSS:3.1"),
        ("CVSS:3.1/AV:N/AC:L", "missing CVSS base metrics"),
        ("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "AV:X"),
        ("CVSS:3.1/AV:N/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "duplicate"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H", "unsupported"),
    ],
)
def test_rejects_incomplete_or_non_base_vectors(vector, message):
    with pytest.raises(CVSSVectorError, match=message):
        assess(vector)
