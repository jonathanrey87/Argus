"""Conservative WordPress REST authorization fact extraction."""

from __future__ import annotations

import re
from pathlib import Path

from dataclasses import dataclass

from astranyx.analysis.authorization import (
    AccessPath,
    AuthorizationControl,
    AuthorizationDifferential,
    AuthorizationDifferentialAnalyzer,
    AuthorizationPolicy,
)


REGISTER = re.compile(r"\bregister_rest_route\s*\(")
FUNCTION = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\([^)]*\)")
ARRAY_CALLBACK = re.compile(
    r"['\"](?P<key>permission_callback|callback)['\"]\s*=>\s*"
    r"(?:\[|array\()\s*(?:\$this|[A-Za-z_\\][\w\\]*)\s*,\s*"
    r"['\"](?P<name>[A-Za-z_]\w*)['\"]\s*(?:\]|\))"
)
STRING_CALLBACK = re.compile(
    r"['\"](?P<key>permission_callback|callback)['\"]\s*=>\s*"
    r"['\"](?P<name>[A-Za-z_][\w:]*)['\"]"
)
METHOD = re.compile(r"['\"]methods['\"]\s*=>\s*([^,\]\n]+)")
CURRENT_USER_CAN = re.compile(
    r"\bcurrent_user_can\s*\(\s*['\"](?P<capability>[^'\"]+)['\"]"
)
AUTHENTICATED = re.compile(r"\b(?:is_user_logged_in|wp_get_current_user)\s*\(")
POLICY_CALL = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*user_can_[A-Za-z_]\w*)\s*\("
)
POST_TYPE_CONSTANT = re.compile(r"::PT_(?P<name>[A-Z][A-Z0-9_]*)\b")
POST_TYPE_LITERAL = re.compile(
    r"['\"]post_type['\"]\s*=>\s*['\"](?P<name>[a-z][a-z0-9_-]*)['\"]"
)
POLICY_NAME = re.compile(
    r"user_can_(?P<verb>view|browse|read|edit|update|delete|manage)_"
    r"(?P<asset>[a-z][a-z0-9_]*)"
)


@dataclass(frozen=True, slots=True)
class WordPressAuthorizationInventory:
    """Correlated authorization facts extracted from one plugin."""

    paths: tuple[AccessPath, ...]
    policies: tuple[AuthorizationPolicy, ...]
    differentials: tuple[AuthorizationDifferential, ...]


def _balanced_call(text: str, start: int) -> str:
    """Return one balanced call while ignoring delimiters inside strings."""
    opening = text.find("(", start)
    if opening < 0:
        return ""
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening, len(text)):
        character = text[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return ""


def _top_level_arguments(call: str) -> list[str]:
    opening = call.find("(")
    closing = call.rfind(")")
    if opening < 0 or closing <= opening:
        return []
    arguments: list[str] = []
    start = opening + 1
    depths = {"(": 0, "[": 0, "{": 0}
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = ""
    escaped = False
    for index in range(start, closing):
        character = call[index]
        if quote:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            continue
        if character in {"'", '"'}:
            quote = character
        elif character in depths:
            depths[character] += 1
        elif character in pairs:
            depths[pairs[character]] -= 1
        elif character == "," and not any(depths.values()):
            arguments.append(call[start:index].strip())
            start = index + 1
    arguments.append(call[start:closing].strip())
    return arguments


def _literal(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _callback(call: str, key: str) -> str:
    for pattern in (ARRAY_CALLBACK, STRING_CALLBACK):
        for match in pattern.finditer(call):
            if match.group("key") == key:
                return match.group("name")
    return ""


def _method(call: str) -> str:
    match = METHOD.search(call)
    if not match:
        return "GET"
    value = match.group(1).strip()
    constants = {
        "WP_REST_Server::READABLE": "GET",
        "WP_REST_Server::CREATABLE": "POST",
        "WP_REST_Server::EDITABLE": "PUT/PATCH",
        "WP_REST_Server::DELETABLE": "DELETE",
        "WP_REST_Server::ALLMETHODS": "*",
    }
    if value in constants:
        return constants[value]
    literal = _literal(value)
    return literal.upper() if literal else "GET"


def _function_bodies(text: str) -> dict[str, str]:
    bodies: dict[str, str] = {}
    for match in FUNCTION.finditer(text):
        opening = text.find("{", match.end())
        if opening < 0:
            continue
        depth = 0
        for index in range(opening, len(text)):
            depth += text[index] == "{"
            depth -= text[index] == "}"
            if depth == 0:
                bodies[match.group(1)] = text[opening : index + 1]
                break
    return bodies


def _controls(
    callback: str, bodies: dict[str, str]
) -> tuple[AuthorizationControl, ...]:
    body = bodies.get(callback, "")
    controls: dict[str, AuthorizationControl] = {}
    for match in CURRENT_USER_CAN.finditer(body):
        capability = match.group("capability")
        identifier = f"capability:{capability}"
        controls[identifier] = AuthorizationControl(
            identifier, "capability", match.group(0)
        )
    if AUTHENTICATED.search(body):
        controls["authentication:wordpress-user"] = AuthorizationControl(
            "authentication:wordpress-user",
            "authentication",
            "callback checks the current WordPress user",
        )
    for match in POLICY_CALL.finditer(body):
        name = match.group("name")
        identifier = f"capability-function:{name}"
        controls[identifier] = AuthorizationControl(
            identifier, "capability", match.group(0)
        )
    return tuple(controls[key] for key in sorted(controls))


def _asset_from_body(body: str) -> str:
    """Resolve a WordPress object type only from concrete implementation facts."""
    constant = POST_TYPE_CONSTANT.search(body)
    if constant:
        name = constant.group("name").casefold()
        # WP Job Manager uses PT_LISTING for the job_listing post type.
        name = "job_listing" if name == "listing" else name
        return f"wordpress-post-type:{name}"
    literal = POST_TYPE_LITERAL.search(body)
    if literal:
        return f"wordpress-post-type:{literal.group('name')}"
    for match in POLICY_CALL.finditer(body):
        parsed = POLICY_NAME.search(match.group("name"))
        if parsed:
            return f"wordpress-post-type:{parsed.group('asset').rstrip('s')}"
    return ""


def _operation(method: str, route: str) -> str:
    normalized = method.upper()
    if normalized == "GET":
        return "read_item" if "(?P<" in route else "read_collection"
    if normalized == "DELETE":
        return "delete"
    if normalized in {"PUT", "PATCH", "PUT/PATCH"}:
        return "update"
    if normalized == "POST":
        return "create"
    return "request"


def _policy_operation(verb: str) -> str:
    return {
        "view": "read_item",
        "read": "read_item",
        "browse": "read_collection",
        "edit": "update",
        "update": "update",
        "delete": "delete",
        "manage": "update",
    }[verb]


def _infer_policies(
    files: list[tuple[str, str]],
) -> list[AuthorizationPolicy]:
    """Infer contracts from explicit plugin authorization function calls."""
    grouped: dict[tuple[str, str], dict[str, AuthorizationControl]] = {}
    evidence: dict[tuple[str, str], set[str]] = {}
    for file_name, text in files:
        for match in POLICY_CALL.finditer(text):
            name = match.group("name")
            parsed = POLICY_NAME.search(name)
            if not parsed:
                continue
            asset_name = parsed.group("asset").rstrip("s")
            if asset_name == "job_listing":
                asset_name = "job_listing"
            asset = f"wordpress-post-type:{asset_name}"
            operation = _policy_operation(parsed.group("verb"))
            key = (asset, operation)
            identifier = f"capability-function:{name}"
            grouped.setdefault(key, {})[identifier] = AuthorizationControl(
                identifier, "capability", match.group(0)
            )
            line = text.count("\n", 0, match.start()) + 1
            evidence.setdefault(key, set()).add(f"{name} at {file_name}:{line}")

    policies = []
    for (asset, operation), controls in sorted(grouped.items()):
        # Different named policy functions may encode alternatives or distinct
        # contexts. Refuse to invent an AND relationship between them.
        if len(controls) != 1:
            continue
        policies.append(
            AuthorizationPolicy(
                id=f"wordpress-policy:{asset}:{operation}",
                asset=asset,
                operation=operation,
                required_controls=tuple(controls[key] for key in sorted(controls)),
                evidence="; ".join(sorted(evidence[(asset, operation)])),
            )
        )
    return policies


def extract_rest_access_paths(
    path: Path, *, root: Path | None = None
) -> list[AccessPath]:
    """Extract registered REST paths and controls proven inside their callbacks."""
    resolved = path.resolve()
    file_name = str(resolved.relative_to(root.resolve())) if root else str(resolved)
    text = resolved.read_text(encoding="utf-8", errors="ignore")
    bodies = _function_bodies(text)
    paths: list[AccessPath] = []
    for index, match in enumerate(REGISTER.finditer(text), start=1):
        call = _balanced_call(text, match.start())
        arguments = _top_level_arguments(call)
        if len(arguments) < 3:
            continue
        namespace = _literal(arguments[0]).strip("/")
        route = _literal(arguments[1])
        callback = _callback(call, "callback")
        permission = _callback(call, "permission_callback")
        callback_body = bodies.get(callback, "")
        permission_body = bodies.get(permission, "")
        controls = {
            control.id: control
            for name in (permission, callback)
            for control in _controls(name, bodies)
        }
        public = permission == "__return_true"
        line = text.count("\n", 0, match.start()) + 1
        full_route = f"/{namespace}/{route.lstrip('/')}"
        method = _method(call)
        asset = _asset_from_body(f"{callback_body}\n{permission_body}")
        evidence = (
            "permission_callback is __return_true"
            if public
            else f"permission callback: {permission or 'not explicitly resolved'}"
        )
        paths.append(
            AccessPath(
                id=f"wordpress-rest:{file_name}:{line}:{index}",
                asset=asset or f"wordpress-rest:{callback or full_route}",
                operation=_operation(method, full_route),
                route=full_route,
                method=method,
                controls=tuple(controls[key] for key in sorted(controls)),
                exposure="public" if public else "unknown",
                file=file_name,
                line=line,
                evidence=evidence,
            )
        )
    return paths


def extract_plugin_access_paths(
    root: Path, *, recursive: bool = True
) -> list[AccessPath]:
    """Extract REST access paths from the PHP files in a WordPress plugin."""
    resolved = root.expanduser().resolve()
    files = resolved.rglob("*.php") if recursive else resolved.glob("*.php")
    paths: list[AccessPath] = []
    for path in sorted(files):
        if any(part in {"vendor", "node_modules", ".git"} for part in path.parts):
            continue
        paths.extend(extract_rest_access_paths(path, root=resolved))
    return paths


def analyze_plugin_authorization(
    root: Path, *, recursive: bool = True
) -> WordPressAuthorizationInventory:
    """Extract and correlate explicit WordPress authorization contracts."""
    resolved = root.expanduser().resolve()
    candidates = resolved.rglob("*.php") if recursive else resolved.glob("*.php")
    files: list[tuple[str, str]] = []
    paths: list[AccessPath] = []
    for path in sorted(candidates):
        if any(part in {"vendor", "node_modules", ".git"} for part in path.parts):
            continue
        file_name = str(path.relative_to(resolved))
        text = path.read_text(encoding="utf-8", errors="ignore")
        files.append((file_name, text))
        paths.extend(extract_rest_access_paths(path, root=resolved))
    policies = _infer_policies(files)
    differentials = AuthorizationDifferentialAnalyzer().analyze(paths, policies)
    return WordPressAuthorizationInventory(
        tuple(paths), tuple(policies), tuple(differentials)
    )
