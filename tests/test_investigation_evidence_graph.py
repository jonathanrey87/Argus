from astranyx.investigation import evidence_graph


def test_build_links_modules_findings_files_and_shared_evidence():
    graph = evidence_graph.build(
        {
            "findings": [
                {
                    "fingerprint": "asx-one",
                    "category": "SSRF",
                    "severity": "High",
                    "confidence": 90,
                    "file": "src/plugin.php",
                    "evidence": "request($url)",
                    "modules": ["wordpress", "javascript"],
                    "fingerprint_collision": False,
                },
                {
                    "fingerprint": "asx-two",
                    "category": "SSRF",
                    "severity": "Medium",
                    "confidence": 70,
                    "file": "src/other.php",
                    "evidence": "request($url)",
                    "modules": ["wordpress"],
                    "fingerprint_collision": False,
                },
            ]
        }
    )

    assert graph["summary"] == {
        "nodes": 7,
        "edges": 7,
        "node_types": {"evidence": 1, "file": 2, "finding": 2, "module": 2},
    }
    assert {
        (edge["source"], edge["target"], edge["type"])
        for edge in graph["edges"]
    } >= {
        ("module:wordpress", "finding:asx-one", "reported"),
        ("module:javascript", "finding:asx-one", "reported"),
    }


def test_build_gives_collisions_distinct_finding_nodes():
    finding = {
        "fingerprint": "asx-collision",
        "category": "SSRF",
        "severity": "High",
        "confidence": 90,
        "modules": ["wordpress"],
        "fingerprint_collision": True,
    }
    graph = evidence_graph.build(
        {
            "findings": [
                {**finding, "file": "one.php", "evidence": "first"},
                {**finding, "file": "two.php", "evidence": "second"},
            ]
        }
    )

    finding_nodes = [node for node in graph["nodes"] if node["type"] == "finding"]
    assert len(finding_nodes) == 2
    assert finding_nodes[0]["id"] != finding_nodes[1]["id"]


def test_build_preserves_repeated_unfingerprinted_findings():
    finding = {
        "category": "Manual observation",
        "file": "notes.txt",
        "evidence": "same note",
        "modules": ["manual"],
    }
    graph = evidence_graph.build({"findings": [finding, finding]})

    finding_nodes = [node for node in graph["nodes"] if node["type"] == "finding"]
    assert len(finding_nodes) == 2
    assert any(node["id"].endswith(":2") for node in finding_nodes)
