from astranyx.telemetry import Status, StatusCode, _PrivacySafeSpan
from astranyx.tracing import configure_tracing


class RecordingSpan:
    def __init__(self):
        self.attributes = {}
        self.statuses = []
        self.exceptions = []

    def set_attribute(self, name, value):
        self.attributes[name] = value

    def set_status(self, status):
        self.statuses.append(status)

    def record_exception(self, exception):
        self.exceptions.append(exception)


def test_tracing_disabled_without_credentials(
    monkeypatch,
):
    monkeypatch.delenv("ARIZE_SPACE_ID", raising=False)
    monkeypatch.delenv("ARIZE_API_KEY", raising=False)
    monkeypatch.delenv("ASTRANYX_TELEMETRY", raising=False)

    assert configure_tracing() is None


def test_tracing_registers_with_credentials(
    monkeypatch,
):
    captured = {}

    def fake_register(**kwargs):
        captured.update(kwargs)

    monkeypatch.setenv("ARIZE_SPACE_ID", "test-space")
    monkeypatch.setenv("ARIZE_API_KEY", "test-key")
    monkeypatch.setenv("ASTRANYX_TELEMETRY", "true")
    monkeypatch.setattr(
        "astranyx.tracing.register",
        fake_register,
    )

    tracer = configure_tracing()

    assert tracer is not None
    assert captured == {
        "space_id": "test-space",
        "api_key": "test-key",
        "project_name": "astranyx",
    }


def test_credentials_do_not_implicitly_enable_telemetry(monkeypatch):
    monkeypatch.setenv("ARIZE_SPACE_ID", "test-space")
    monkeypatch.setenv("ARIZE_API_KEY", "test-key")
    monkeypatch.delenv("ASTRANYX_TELEMETRY", raising=False)

    assert configure_tracing() is None


def test_privacy_filter_drops_customer_identifiers_and_exceptions():
    backend = RecordingSpan()
    span = _PrivacySafeSpan(backend)

    span.set_attribute("astranyx.command", "assess")
    span.set_attribute("astranyx.target", "Confidential Client")
    span.set_attribute("astranyx.file.path", "/private/client/source.js")
    span.record_exception(RuntimeError("secret evidence"))
    span.set_status(Status(StatusCode.ERROR, "/private/client/source.js"))

    assert backend.attributes == {"astranyx.command": "assess"}
    assert backend.exceptions == []
    assert backend.statuses[0].description is None
