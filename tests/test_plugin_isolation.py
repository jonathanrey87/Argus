import hashlib
import json
import os
import subprocess
import sys

import pytest

from astranyx.cli import main
from astranyx.plugin_runtime import (
    IsolatedPluginRunner,
    PluginError,
    PluginManifest,
    sign_manifest,
    verify_signature,
)


def write_plugin(tmp_path, **overrides):
    root = tmp_path / "plugin"
    root.mkdir()
    entrypoint = root / "main.py"
    entrypoint.write_text(
        'import json, sys\nrequest=json.load(sys.stdin)\nprint(json.dumps({"inputs": request["inputs"]}))\n'
    )
    manifest = {
        "schema_version": 1,
        "name": "test-plugin",
        "version": "1.0.0",
        "entrypoint": "main.py",
        "entrypoint_sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
        "read_inputs": False,
        "write_output": False,
        "network": False,
        "timeout_seconds": 10,
        "cpu_seconds": 5,
        "memory_mib": 64,
        "max_output_bytes": 4096,
    }
    manifest.update(overrides)
    (root / "plugin.json").write_text(json.dumps(manifest))
    return root


def write_keys(tmp_path, key_id="publisher"):
    private = tmp_path / "private.pem"
    keyring = tmp_path / "keyring"
    keyring.mkdir(parents=True)
    os.chmod(keyring, 0o700)
    public = keyring / f"{key_id}.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        check=True,
        capture_output=True,
    )
    os.chmod(private, 0o600)
    subprocess.run(
        ["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        check=True,
        capture_output=True,
    )
    os.chmod(public, 0o644)
    return private, keyring


def test_manifest_validates_entrypoint_digest_and_capabilities(tmp_path):
    root = write_plugin(tmp_path)
    manifest, resolved = PluginManifest.load(root)
    assert manifest.name == "test-plugin"
    assert resolved == root.resolve()
    (root / "main.py").write_text("tampered")
    with pytest.raises(PluginError, match="digest mismatch"):
        PluginManifest.load(root)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"network": True}, "network access"),
        ({"entrypoint": "../escape.py"}, "relative Python"),
        ({"timeout_seconds": 301}, "timeout"),
        ({"memory_mib": 16}, "memory"),
        ({"unexpected": True}, "unknown"),
        ({"read_inputs": "false"}, "JSON booleans"),
        ({"memory_mib": "64"}, "JSON integers"),
    ],
)
def test_manifest_rejects_unsafe_declarations(tmp_path, overrides, message):
    root = write_plugin(tmp_path, **overrides)
    with pytest.raises(PluginError, match=message):
        PluginManifest.load(root)


def test_command_mounts_only_declared_inputs_and_output(tmp_path):
    root = write_plugin(tmp_path, read_inputs=True, write_output=True)
    manifest, plugin_root = PluginManifest.load(root)
    source = tmp_path / "input.txt"
    source.write_text("input")
    output = tmp_path / "output"
    output.mkdir()
    command, invocation = IsolatedPluginRunner("/usr/bin/bwrap").build_command(
        manifest, plugin_root, [source], output
    )
    assert "--unshare-all" in command
    assert [str(source.resolve()), "/inputs/0000"] == command[
        command.index(str(source.resolve())) : command.index(str(source.resolve())) + 2
    ]
    assert invocation == {"inputs": ["/inputs/0000"], "output": "/output"}


def test_capability_mismatch_is_denied_before_execution(tmp_path):
    root = write_plugin(tmp_path)
    manifest, plugin_root = PluginManifest.load(root)
    source = tmp_path / "input.txt"
    source.write_text("input")
    with pytest.raises(PluginError, match="read_inputs"):
        IsolatedPluginRunner("/usr/bin/bwrap").build_command(
            manifest, plugin_root, [source], None
        )


def test_backend_failure_is_fail_closed(tmp_path, monkeypatch):
    root = write_plugin(tmp_path)
    private, keyring = write_keys(tmp_path)
    sign_manifest(root, private, "publisher")
    runner = IsolatedPluginRunner("/missing/bwrap", keyring=keyring)
    with pytest.raises(PluginError, match="backend unavailable"):
        runner.run(root)


def test_signed_manifest_verifies_against_trusted_publisher(tmp_path):
    root = write_plugin(tmp_path)
    private, keyring = write_keys(tmp_path)
    manifest = sign_manifest(root, private, "publisher")
    verify_signature(manifest, keyring)
    assert manifest.signature_algorithm == "ed25519"
    assert manifest.publisher_key_id == "publisher"


def test_signature_rejects_manifest_tampering_and_untrusted_key(tmp_path):
    root = write_plugin(tmp_path)
    private, keyring = write_keys(tmp_path)
    sign_manifest(root, private, "publisher")
    document = json.loads((root / "plugin.json").read_text())
    document["timeout_seconds"] = 11
    (root / "plugin.json").write_text(json.dumps(document))
    manifest, _ = PluginManifest.load(root)
    with pytest.raises(PluginError, match="verification failed"):
        verify_signature(manifest, keyring)

    other_private, other_keyring = write_keys(tmp_path / "other")
    assert other_private.exists()
    with pytest.raises(PluginError, match="verification failed"):
        verify_signature(sign_manifest(root, private, "publisher"), other_keyring)


def test_runner_requires_trusted_keyring_before_isolation(tmp_path):
    root = write_plugin(tmp_path)
    with pytest.raises(PluginError, match="keyring"):
        IsolatedPluginRunner("/missing/bwrap").run(root)


def test_cli_validates_plugin_without_executing_it(tmp_path, monkeypatch, capsys):
    root = write_plugin(tmp_path)
    monkeypatch.setattr(sys, "argv", ["astranyx", "plugin", "validate", str(root)])
    main()
    assert json.loads(capsys.readouterr().out)["name"] == "test-plugin"
