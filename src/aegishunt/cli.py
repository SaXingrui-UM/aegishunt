"""Command-line entry point for the Phase 0 application shells."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated

import typer
import uvicorn

from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME

app = typer.Typer(
    name="aegishunt",
    help=f"{APPLICATION_NAME}: {APPLICATION_DESCRIPTION}",
    no_args_is_help=True,
)

REQUIRED_DIRECTORIES = ("configs", "data", "artifacts", "reports")


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Structured result from the local foundation checks."""

    python_version: str
    python_supported: bool
    operating_system: str
    machine: str
    project_root: str
    directories: dict[str, bool]

    @property
    def healthy(self) -> bool:
        """Return whether all Phase 0 prerequisites are present."""

        return self.python_supported and all(self.directories.values())

    def to_json(self) -> str:
        """Serialize the report for readable CLI output."""

        return json.dumps({**asdict(self), "healthy": self.healthy}, indent=2, sort_keys=True)


def collect_doctor_report(project_root: Path | None = None) -> DoctorReport:
    """Inspect Python, the operating system, and required project directories."""

    root = (project_root or Path.cwd()).resolve()
    return DoctorReport(
        python_version=platform.python_version(),
        python_supported=sys.version_info >= (3, 11),
        operating_system=platform.system(),
        machine=platform.machine(),
        project_root=str(root),
        directories={name: (root / name).is_dir() for name in REQUIRED_DIRECTORIES},
    )


def run_api(host: str, port: int, reload: bool) -> None:
    """Run the minimal FastAPI application."""

    uvicorn.run("aegishunt.api.app:app", host=host, port=port, reload=reload)


def run_frontend(address: str, port: int, headless: bool) -> int:
    """Run the minimal Streamlit page in a child Python process."""

    script = Path(__file__).resolve().parent / "frontend" / "app.py"
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(script),
        "--server.address",
        address,
        "--server.port",
        str(port),
        "--server.headless",
        str(headless).lower(),
    ]
    return subprocess.run(command, check=False).returncode


@app.command()
def doctor() -> None:
    """Check the Python runtime, operating system, and foundation directories."""

    report = collect_doctor_report()
    typer.echo(report.to_json())
    if not report.healthy:
        raise typer.Exit(code=1)


@app.command()
def api(
    host: Annotated[str, typer.Option(help="Interface on which the API listens.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535, help="API TCP port.")] = 8000,
    reload: Annotated[
        bool,
        typer.Option("--reload/--no-reload", help="Reload when source files change."),
    ] = False,
) -> None:
    """Start the minimal FastAPI application."""

    run_api(host=host, port=port, reload=reload)


@app.command()
def frontend(
    address: Annotated[
        str,
        typer.Option(help="Interface on which Streamlit listens."),
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535, help="Streamlit TCP port.")] = 8501,
    headless: Annotated[
        bool,
        typer.Option("--headless/--no-headless", help="Run without opening a browser."),
    ] = True,
) -> None:
    """Start the minimal Streamlit research-prototype page."""

    exit_code = run_frontend(address=address, port=port, headless=headless)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
