"""Bootstrap source-checkout runs into a local virtual environment."""

from __future__ import annotations

import importlib.metadata as metadata
import os
import subprocess
import sys
import venv
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError
from pathlib import Path


@dataclass(frozen=True)
class RequirementPin:
    """Exact dependency pin from requirements.txt."""

    name: str
    version: str


@dataclass(frozen=True)
class RequirementStatus:
    """Dependency status that requires installation."""

    name: str
    required_version: str
    installed_version: str | None


def project_root() -> Path:
    """Return the repository root for a source checkout."""
    return Path(__file__).resolve().parents[1]


def current_executable() -> Path:
    """Return the active Python executable."""
    return Path(sys.executable)


def target_venv_dir(root: Path) -> Path:
    """Return the virtual environment path used by the launcher."""
    configured = os.environ.get("WILL_ENCRYPT_VENV")
    if configured:
        return Path(configured).expanduser().resolve()
    return root / ".venv"


def venv_python(venv_dir: Path) -> Path:
    """Return the Python executable path inside a virtual environment."""
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def parse_requirement_pins(lines: Sequence[str]) -> tuple[RequirementPin, ...]:
    """Parse exact pins from a pip requirements file."""
    pins: list[RequirementPin] = []
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-r "):
            continue
        if "==" not in line:
            continue
        name, version = line.split("==", 1)
        pins.append(RequirementPin(name.strip(), version.strip()))
    return tuple(pins)


def load_requirement_pins(requirements_path: Path) -> tuple[RequirementPin, ...]:
    """Load runtime dependency pins from requirements.txt."""
    return parse_requirement_pins(requirements_path.read_text(encoding="utf-8").splitlines())


def missing_requirements(pins: Sequence[RequirementPin]) -> tuple[RequirementStatus, ...]:
    """Return requirements that are not installed at the pinned version."""
    missing: list[RequirementStatus] = []
    for pin in pins:
        try:
            installed_version = metadata.version(pin.name)
        except PackageNotFoundError:
            missing.append(RequirementStatus(pin.name, pin.version, None))
            continue
        if installed_version != pin.version:
            missing.append(RequirementStatus(pin.name, pin.version, installed_version))
    return tuple(missing)


def create_venv(venv_dir: Path) -> None:
    """Create a venv with pip for runtime dependencies."""
    print(f"Creating local Python environment: {venv_dir}", file=sys.stderr)
    venv.EnvBuilder(with_pip=True).create(venv_dir)


def install_requirements(python: Path, requirements_path: Path) -> None:
    """Install runtime requirements into the target Python environment."""
    print("Installing will-encrypt runtime dependencies...", file=sys.stderr)
    subprocess.run(
        [str(python), "-m", "ensurepip", "--upgrade"],
        check=True,
    )
    subprocess.run(
        [str(python), "-m", "pip", "install", "-r", str(requirements_path)],
        check=True,
    )


def exec_module(python: Path, module: str, args: Sequence[str]) -> None:
    """Replace the current process with a Python module invocation."""
    os.execv(str(python), [str(python), "-m", module, *args])


def format_missing(missing: Sequence[RequirementStatus]) -> str:
    """Format unresolved dependencies for error output."""
    details = []
    for item in missing:
        if item.installed_version is None:
            details.append(f"{item.name}=={item.required_version} (not installed)")
        else:
            details.append(
                f"{item.name}=={item.required_version} "
                f"(installed {item.installed_version})"
            )
    return ", ".join(details)


def run(args: Sequence[str]) -> int:
    """Prepare the local venv and dispatch to the main CLI."""
    if sys.version_info < (3, 11):  # noqa: UP036 - bootstrap may run before project metadata applies.
        print(
            "Python 3.11+ is required. Install a supported Python version and retry "
            "./will-encrypt.",
            file=sys.stderr,
        )
        return 1

    root = project_root()
    requirements_path = root / "requirements.txt"
    if not requirements_path.exists():
        exec_module(current_executable(), "src.main", args)
        return 0

    venv_dir = target_venv_dir(root)
    python = venv_python(venv_dir)
    active_python = current_executable()

    if active_python.resolve() != python.resolve():
        try:
            if not python.exists():
                create_venv(venv_dir)
        except OSError as exc:
            print(
                "Could not create the local Python environment. "
                f"Install Python 3.11+ with venv support and retry. Error: {exc}",
                file=sys.stderr,
            )
            return 1
        exec_module(python, "src.bootstrap", args)
        return 0

    pins = load_requirement_pins(requirements_path)
    missing = missing_requirements(pins)
    if missing:
        try:
            install_requirements(active_python, requirements_path)
        except subprocess.CalledProcessError as exc:
            print(
                "Could not install runtime dependencies. "
                f"Check network access and retry ./will-encrypt. Error: {exc}",
                file=sys.stderr,
            )
            return 1
        missing = missing_requirements(pins)
        if missing:
            print(
                "Could not satisfy runtime dependencies after installation: "
                f"{format_missing(missing)}. Retry ./will-encrypt or install manually with "
                f"{active_python} -m pip install -r {requirements_path}.",
                file=sys.stderr,
            )
            return 1

    exec_module(active_python, "src.main", args)
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
