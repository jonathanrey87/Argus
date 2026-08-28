from astranyx.core.finding import Finding
from astranyx.mobile.masvs import MASVS_VERSION, exact_controls, infer_group


def test_extracts_only_explicit_masvs_controls():
    assert exact_controls("MASVS-NETWORK-1, MSTG-NETWORK-2, MASVS-AUTH-2") == [
        "MASVS-AUTH-2",
        "MASVS-NETWORK-1",
    ]
    assert MASVS_VERSION == "2.1.0"


def test_signing_certificate_is_not_misclassified_as_network():
    assert infer_group("Application signed with debug certificate") == [
        "MASVS-RESILIENCE"
    ]


def test_infers_broad_group_without_fabricating_control():
    assert infer_group("Cleartext network traffic") == ["MASVS-NETWORK"]
    assert infer_group("Unclassified observation") == []


def test_finding_records_inferred_and_upstream_mapping_basis():
    inferred = Finding(
        category="Insecure local storage",
        severity="High",
        file="app.java",
        full_path="",
        line=1,
        evidence="Stored token",
        note="Review",
    )
    upstream = Finding(
        category="Network traffic",
        severity="High",
        file="app.java",
        full_path="",
        line=1,
        evidence="Cleartext request",
        note="Review",
        masvs=["MASVS-NETWORK-1"],
        masvs_mapping="upstream",
    )

    assert inferred.masvs == ["MASVS-STORAGE"]
    assert inferred.masvs_mapping == "inferred"
    assert upstream.masvs == ["MASVS-NETWORK-1"]
    assert upstream.masvs_mapping == "upstream"
