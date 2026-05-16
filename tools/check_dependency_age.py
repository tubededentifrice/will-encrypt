#!/usr/bin/env python3
"""Enforce dependency pinning and minimum PyPI release age."""

from __future__ import annotations

import argparse
import email.message
import importlib.metadata
import json
import re
import sys
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import urlopen

PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^;\s#]+)")
INCLUDE_RE = re.compile(r"^\s*-r\s+(.+?)\s*(?:#.*)?$")


@dataclass(frozen=True)
class RequirementPin:
    name: str
    version: str
    source: str

    @property
    def normalized_name(self) -> str:
        return normalize_name(self.name)


def normalize_name(name: str) -> str:
    """Normalize package names the same way Python packaging tools do."""
    return re.sub(r"[-_.]+", "-", name).lower()


def iter_requirement_lines(path: Path, seen: set[Path] | None = None) -> Iterable[tuple[str, str]]:
    """Yield requirement lines, expanding local -r includes."""
    seen = seen or set()
    path = path.resolve()
    if path in seen:
        return
    seen.add(path)

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        include_match = INCLUDE_RE.match(stripped)
        if include_match:
            include_path = (path.parent / include_match.group(1)).resolve()
            yield from iter_requirement_lines(include_path, seen)
            continue
        yield stripped, f"{path}:{line_number}"


def parse_requirement_pins(paths: Iterable[Path]) -> list[RequirementPin]:
    """Parse exact pins from requirements files."""
    pins: list[RequirementPin] = []
    errors: list[str] = []

    for path in paths:
        for line, source in iter_requirement_lines(path):
            match = PIN_RE.match(line)
            if not match:
                errors.append(f"{source}: requirement must be exactly pinned with ==: {line!r}")
                continue
            pins.append(RequirementPin(match.group(1), match.group(2), source))

    if errors:
        raise ValueError("\n".join(errors))
    return pins


def parse_pyproject_pins(path: Path) -> list[RequirementPin]:
    """Parse exact pins from project, build, and optional dependency metadata."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries: list[tuple[str, str]] = []
    build_requirements = data.get("build-system", {}).get("requires", [])
    project_requirements = data.get("project", {}).get("dependencies", [])
    entries.extend((req, "build-system.requires") for req in build_requirements)
    entries.extend((req, "project.dependencies") for req in project_requirements)
    for extra, requirements in data.get("project", {}).get("optional-dependencies", {}).items():
        entries.extend((req, f"project.optional-dependencies.{extra}") for req in requirements)

    pins: list[RequirementPin] = []
    errors: list[str] = []
    for requirement, source in entries:
        match = PIN_RE.match(requirement)
        if not match:
            errors.append(
                f"{path}:{source}: requirement must be exactly pinned with ==: {requirement!r}"
            )
            continue
        pins.append(RequirementPin(match.group(1), match.group(2), f"{path}:{source}"))

    if errors:
        raise ValueError("\n".join(errors))
    return pins


def latest_upload_time(package_name: str, version: str) -> datetime:
    """Return the newest file upload timestamp for a PyPI release."""
    url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    try:
        with urlopen(url, timeout=20) as response:
            payload = json.load(response)
    except HTTPError as exc:
        raise RuntimeError(
            f"PyPI lookup failed for {package_name}=={version}: HTTP {exc.code}"
        ) from exc
    except URLError as exc:
        raise RuntimeError(
            f"PyPI lookup failed for {package_name}=={version}: {exc.reason}"
        ) from exc

    uploads = [
        datetime.fromisoformat(file_info["upload_time_iso_8601"].replace("Z", "+00:00"))
        for file_info in payload.get("urls", [])
        if file_info.get("upload_time_iso_8601")
    ]
    if not uploads:
        raise RuntimeError(f"PyPI release has no upload timestamps: {package_name}=={version}")
    return max(uploads)


def metadata_requirements(dist: importlib.metadata.Distribution) -> list[str]:
    """Read Requires-Dist values from installed distribution metadata."""
    metadata = dist.metadata
    assert isinstance(metadata, email.message.Message)
    return metadata.get_all("Requires-Dist") or []


def marker_applies(requirement: str) -> bool:
    """Best-effort environment marker evaluation without importing packaging."""
    if ";" not in requirement:
        return True
    marker = requirement.split(";", 1)[1].strip()
    if not marker:
        return True
    try:
        from packaging.markers import Marker
    except ImportError as exc:
        raise RuntimeError("Installed-mode checks require packaging for marker evaluation") from exc
    return Marker(marker).evaluate()


def dependency_name(requirement: str) -> str:
    """Extract a distribution name from a Requires-Dist value."""
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
    if not match:
        raise ValueError(f"Could not parse dependency name from {requirement!r}")
    return normalize_name(match.group(1))


def installed_closure(root_names: Iterable[str]) -> list[RequirementPin]:
    """Return installed direct and transitive distributions reachable from roots."""
    distributions = {
        normalize_name(dist.metadata["Name"]): dist for dist in importlib.metadata.distributions()
    }
    seen: set[str] = set()
    stack = [normalize_name(name) for name in root_names]
    pins: list[RequirementPin] = []

    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        dist = distributions.get(name)
        if dist is None:
            raise ValueError(f"Installed distribution not found: {name}")
        pins.append(RequirementPin(dist.metadata["Name"], dist.version, "installed"))
        for requirement in metadata_requirements(dist):
            if marker_applies(requirement):
                stack.append(dependency_name(requirement))

    return pins


def dedupe_pins(pins: Iterable[RequirementPin]) -> list[RequirementPin]:
    """Deduplicate pins and reject conflicting pinned versions."""
    by_name: dict[str, RequirementPin] = {}
    conflicts: list[str] = []
    for pin in pins:
        existing = by_name.get(pin.normalized_name)
        if existing and existing.version != pin.version:
            conflicts.append(
                f"{pin.name} has conflicting pins: {existing.version} ({existing.source})"
                f" vs {pin.version} ({pin.source})"
            )
            continue
        by_name[pin.normalized_name] = existing or pin
    if conflicts:
        raise ValueError("\n".join(conflicts))
    return sorted(by_name.values(), key=lambda pin: pin.normalized_name)


def check_minimum_age(
    pins: Iterable[RequirementPin],
    min_age_days: int,
    now: datetime,
    skip_pypi: set[str] | None = None,
) -> int:
    """Check PyPI upload times for pinned releases."""
    cutoff = now - timedelta(days=min_age_days)
    failures: list[str] = []
    skipped = skip_pypi or set()
    for pin in dedupe_pins(pins):
        if pin.normalized_name in skipped:
            print(f"SKIP {pin.name}=={pin.version} from {pin.source} (not checked on PyPI)")
            continue
        upload_time = latest_upload_time(pin.name, pin.version)
        if upload_time > cutoff:
            failures.append(
                f"{pin.name}=={pin.version} from {pin.source} was uploaded "
                f"{upload_time.date().isoformat()}, newer than cutoff "
                f"{cutoff.date().isoformat()}"
            )
        else:
            print(f"OK {pin.name}=={pin.version} uploaded {upload_time.date().isoformat()}")

    if failures:
        print("\nDependency age check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-age-days", type=int, default=7)
    parser.add_argument("--requirements", nargs="*", type=Path, default=[])
    parser.add_argument("--pyproject", type=Path)
    parser.add_argument(
        "--installed-roots",
        nargs="*",
        default=[],
        help="Installed root distributions whose dependency closure should be checked.",
    )
    parser.add_argument(
        "--skip-pypi",
        nargs="*",
        default=[],
        help="Installed local distributions to traverse but not look up on PyPI.",
    )
    args = parser.parse_args()

    try:
        pins: list[RequirementPin] = []
        if args.requirements:
            pins.extend(parse_requirement_pins(args.requirements))
        if args.pyproject:
            pins.extend(parse_pyproject_pins(args.pyproject))
        if args.installed_roots:
            pins.extend(installed_closure(args.installed_roots))
        if not pins:
            raise ValueError("No dependencies were provided for checking")
        skip_pypi = {normalize_name(name) for name in args.skip_pypi}
        return check_minimum_age(pins, args.min_age_days, datetime.now(UTC), skip_pypi)
    except Exception as exc:
        print(f"Dependency age check failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
