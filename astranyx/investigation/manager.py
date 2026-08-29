import json
from datetime import UTC, datetime
from pathlib import Path


class InvestigationManager:
    def __init__(self, root):
        self.root = Path(root)
        self.metadata_path = self.root / "metadata.json"

        if not self.metadata_path.exists():
            raise FileNotFoundError(self.metadata_path)

        self.load()

    def load(self):
        self.data = json.loads(self.metadata_path.read_text())

    def save(self):
        self.metadata_path.write_text(json.dumps(self.data, indent=2))

    def set_target(self, target):
        self.data["target"] = target
        self.save()

    def set_status(self, status):
        self.data["status"] = status
        self.save()

    def set_context(self, profile, selected_modules):
        """Record how an investigation was orchestrated."""
        self.data["profile"] = profile
        self.data["selected_modules"] = list(selected_modules)
        self.save()

    def record_resume(self, prior_status, modules):
        """Append an auditable record of a resumed pipeline run."""
        self.data.setdefault("resumes", []).append(
            {
                "started": datetime.now(UTC).isoformat(),
                "prior_status": prior_status,
                "modules": list(modules),
            }
        )
        self.data.pop("completed", None)
        self.data["status"] = "active"
        self.save()

    def set_artifacts(self, artifacts):
        """Replace the generated-artifact inventory."""
        self.data["artifacts"] = list(artifacts)
        self.save()

    def add_module(
        self,
        name,
        status="completed",
        duration_ms=None,
        details=None,
    ):
        module = {
            "name": name,
            "status": status,
            "completed": datetime.now(UTC).isoformat(),
        }

        if duration_ms is not None:
            module["duration_ms"] = duration_ms

        if details:
            module.update(details)

        self.data.setdefault("modules", []).append(module)

        self.save()

    def update_findings(
        self,
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
    ):
        findings = self.data["findings"]

        findings["critical"] += critical
        findings["high"] += high
        findings["medium"] += medium
        findings["low"] += low
        findings["info"] += info

        self.save()

    def finish(self):
        self.finish_with_status("completed")

    def finish_with_status(self, status):
        """Complete an investigation with a terminal status."""
        self.data["status"] = status
        self.data["completed"] = datetime.now(UTC).isoformat()
        self.save()
