from __future__ import annotations

from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.table import Table

from ssafer import __version__
from ssafer.core.doctor import collect_doctor_status, install_trivy_with_winget
from ssafer.core.result_store import load_last_scan, run_scan
from ssafer.core.upload import upload_last_scan

app = typer.Typer(help="SSAfer security configuration CLI.")
console = Console()


@app.callback()
def callback() -> None:
    """SSAfer CLI."""


@app.command()
def version() -> None:
    """Print the SSAfer CLI version."""
    console.print(__version__)


@app.command()
def doctor() -> None:
    """Check local tools needed by SSAfer."""
    status = collect_doctor_status()
    table = Table(title="SSAfer doctor")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")
    for item in status["checks"]:
        label = "OK" if item["ok"] else "MISSING"
        table.add_row(item["name"], label, item["detail"])
    console.print(table)
    if not status["trivyFound"]:
        console.print("[yellow]Install Trivy on Windows:[/yellow] ssafer install-tools")


@app.command("install-tools")
def install_tools() -> None:
    """Install optional local tools used by SSAfer."""
    ok, message = install_trivy_with_winget()
    if ok:
        console.print(f"[green]{message}[/green]")
        return
    console.print(f"[red]{message}[/red]")
    raise typer.Exit(code=1)


@app.command()
def run(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Project root to scan."),
    upload: bool = typer.Option(False, "--upload", help="Upload the generated scan package after run."),
    save_raw: bool = typer.Option(False, "--save-raw", help="Store raw effective compose configs locally."),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Backend API base URL for --upload."),
) -> None:
    """Create a local sanitized SSAfer scan package."""
    result = run_scan(path.resolve(), save_raw=save_raw)
    _print_scan_summary(result)
    if upload:
        response = _upload_or_exit(path.resolve(), api_url=api_url)
        _print_upload_response(response)


@app.command()
def upload(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Project root containing .ssafer results."),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Backend API base URL."),
) -> None:
    """Upload the last local scan package."""
    response = _upload_or_exit(path.resolve(), api_url=api_url)
    _print_upload_response(response)


@app.command()
def report(path: Path = typer.Option(Path("."), "--path", "-p", help="Project root containing .ssafer results.")) -> None:
    """Print the last local scan summary."""
    scan = load_last_scan(path.resolve())
    if scan is None:
        console.print("[yellow]No local scan package found.[/yellow]")
        raise typer.Exit(code=1)
    _print_scan_summary(scan)


def _print_scan_summary(scan: dict) -> None:
    summary = scan.get("cliSummary", {})
    table = Table(title=f"SSAfer scan {scan.get('analysisStatus', 'UNKNOWN')}")
    table.add_column("Metric")
    table.add_column("Count")
    for key in ("composeSets", "envFiles", "dockerfiles", "trivyFindings", "warnings"):
        table.add_row(key, str(summary.get(key, 0)))
    console.print(table)
    warnings = scan.get("warnings", [])
    if warnings:
        console.print("[yellow]Warnings[/yellow]")
        for warning in warnings:
            console.print(f"- {warning}")


def _print_upload_response(response: dict) -> None:
    console.print("[green]Upload completed[/green]")
    console.print(f"Scan ID: {response.get('scanId', 'unknown')}")
    if response.get("viewUrl"):
        console.print(f"View: {response['viewUrl']}")


def _upload_or_exit(path: Path, api_url: str | None) -> dict:
    try:
        return upload_last_scan(path, api_url=api_url)
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]Upload failed:[/red] backend returned {exc.response.status_code}")
    except httpx.HTTPError as exc:
        console.print(f"[red]Upload failed:[/red] {exc}")
    except RuntimeError as exc:
        console.print(f"[red]Upload failed:[/red] {exc}")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
