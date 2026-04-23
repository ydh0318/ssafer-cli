from __future__ import annotations

from pathlib import Path
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ssafer import __version__
from ssafer.core.doctor import collect_doctor_status, install_trivy_with_winget
from ssafer.core.result_store import load_last_scan, run_scan
from ssafer.core.upload import upload_last_scan

app = typer.Typer(help="SSAfer security configuration CLI.")
console = Console()

_STATUS_KO = {
    "SUCCESS": "[green]성공[/green]",
    "PARTIAL": "[yellow]부분 성공 (경고 있음)[/yellow]",
    "FAILED": "[red]실패[/red]",
}

_TYPE_KO = {
    "sanitized-effective-compose": "마스킹된 Compose 설정",
    "env-metadata": "환경변수 메타데이터",
    "trivy-json": "Trivy 취약점 결과",
}

_GOOSE = """\
   [bold blue]┌─── SECURITY ───┐[/bold blue]
   [bold blue]└────────────────┘[/bold blue]
  [white]╭──────────────────╮[/white]
  [white]│[/white]  [yellow]◉[/yellow]          [yellow]◉[/yellow]  [white]│[/white]
  [white]│[/white]      [yellow]▶▶[/yellow]        [white]│[/white]
  [white]│[/white]  [blue]╔════════════╗[/blue]  [white]│[/white]  [yellow]≡≡≡[/yellow]
  [white]│[/white]  [blue]║[/blue] [yellow]★[/yellow] [blue]S · E · C ║[/blue]  [white]│[/white]
  [white]│[/white]  [blue]╚════════════╝[/blue]  [white]│[/white]
  [white]╰──────────────────╯[/white]
      [yellow]▐██▌    ▐██▌[/yellow]
     [yellow]▐████▌  ▐████▌[/yellow]"""


def _scan_panel(step: str) -> Panel:
    content = Text.from_markup(f"{_GOOSE}\n\n[bold green]▶  {step}[/bold green]")
    return Panel(
        content,
        title="[bold blue]SSAfer 보안 스캔[/bold blue]",
        border_style="blue",
        padding=(1, 3),
    )


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
    table = Table(title="SSAfer 환경 점검")
    table.add_column("항목")
    table.add_column("상태")
    table.add_column("내용")
    for item in status["checks"]:
        label = "[green]정상[/green]" if item["ok"] else "[red]없음[/red]"
        table.add_row(item["name"], label, item["detail"])
    console.print(table)
    if not status["trivyFound"]:
        console.print("[yellow]Trivy 설치:[/yellow] ssafer install-tools")


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
    with Live(_scan_panel("스캔 준비 중..."), refresh_per_second=8, console=console) as live:
        def on_step(msg: str) -> None:
            live.update(_scan_panel(msg))

        result = run_scan(path.resolve(), save_raw=save_raw, on_step=on_step)

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
def report(
    path: Path = typer.Option(Path("."), "--path", "-p", help="Project root containing .ssafer results."),
    details: bool = typer.Option(False, "--details", "-d", help="Print targets, artifacts, and output paths."),
) -> None:
    """Print the last local scan summary."""
    project_root = path.resolve()
    scan = load_last_scan(project_root)
    if scan is None:
        console.print("[yellow]스캔 결과가 없습니다. 먼저 ssafer run 을 실행해주세요.[/yellow]")
        raise typer.Exit(code=1)
    _print_scan_summary(scan)
    if details:
        _print_scan_details(scan, project_root)


def _print_scan_summary(scan: dict) -> None:
    summary = scan.get("cliSummary", {})
    status = scan.get("analysisStatus", "UNKNOWN")
    status_label = _STATUS_KO.get(status, status)

    table = Table(title=f"스캔 결과  {status_label}")
    table.add_column("항목")
    table.add_column("수량", justify="right")
    rows = [
        ("Compose 세트", "composeSets"),
        ("환경변수 파일 (.env)", "envFiles"),
        ("Dockerfile", "dockerfiles"),
        ("발견된 취약점 수", "trivyFindings"),
        ("경고", "warnings"),
    ]
    for label, key in rows:
        table.add_row(label, str(summary.get(key, 0)))
    console.print(table)

    warnings = scan.get("warnings", [])
    if warnings:
        console.print("[yellow]경고 목록[/yellow]")
        for warning in warnings:
            console.print(f"  - {warning}")


def _print_scan_details(scan: dict, project_root: Path) -> None:
    results_dir = project_root / ".ssafer" / "results"
    last_scan_path = results_dir / f"{scan.get('scanId', 'unknown')}.json"
    marker_path = results_dir / "last_scan.txt"
    sanitized_dir = project_root / ".ssafer" / "effective" / "sanitized"
    trivy_dir = project_root / ".ssafer" / "trivy"

    status = scan.get("analysisStatus", "UNKNOWN")
    status_text = {"SUCCESS": "성공", "PARTIAL": "부분 성공 (경고 있음)", "FAILED": "실패"}.get(status, status)
    trivy = scan.get("toolVersions", {}).get("trivy") or "설치되지 않음"
    docker_compose = scan.get("toolVersions", {}).get("dockerCompose") or "찾을 수 없음"

    console.print()
    console.print(
        Panel.fit(
            "\n".join([
                f"스캔 ID        : {scan.get('scanId', 'unknown')}",
                f"상태           : {status_text}",
                f"SSAfer 버전    : {scan.get('toolVersion', 'unknown')}",
                f"Trivy 버전     : {trivy}",
                f"Docker Compose : {docker_compose}",
            ]),
            title="스캔 정보",
        )
    )

    output_table = Table(title="생성된 파일 위치")
    output_table.add_column("파일 종류")
    output_table.add_column("경로", overflow="fold")
    output_table.add_row("스캔 결과 패키지 (JSON)", str(last_scan_path))
    output_table.add_row("최근 스캔 마커", str(marker_path))
    output_table.add_row("마스킹된 Compose 파일 폴더", str(sanitized_dir))
    output_table.add_row("Trivy 결과 폴더", str(trivy_dir))
    console.print(output_table)

    _print_targets(scan)
    _print_artifacts(scan)


def _print_targets(scan: dict) -> None:
    targets = scan.get("targets", {})

    target_table = Table(title="스캔 대상")
    target_table.add_column("종류")
    target_table.add_column("개수", justify="right")
    target_table.add_column("파일 목록", overflow="fold")
    target_table.add_row(
        "환경변수 파일 (.env)",
        str(len(targets.get("envFiles", []))),
        _join_items(targets.get("envFiles", [])),
    )
    target_table.add_row(
        "Dockerfile",
        str(len(targets.get("dockerfiles", []))),
        _join_items(targets.get("dockerfiles", [])),
    )
    compose_names = [
        f"{item.get('name', 'unknown')} ({', '.join(item.get('files', []))})"
        for item in targets.get("composeSets", [])
    ]
    target_table.add_row("Compose 세트", str(len(compose_names)), _join_items(compose_names))
    console.print(target_table)


def _print_artifacts(scan: dict) -> None:
    artifacts = scan.get("artifacts", [])
    artifact_table = Table(title="수집된 산출물")
    artifact_table.add_column("종류")
    artifact_table.add_column("대상")
    artifact_table.add_column("해시 (앞 12자리)")
    artifact_table.add_column("발견된 취약점 수", justify="right")

    for artifact in artifacts:
        artifact_type = artifact.get("type", "unknown")
        target = artifact.get("target") or artifact.get("composeSet") or "-"
        finding_count = "-"
        if artifact_type == "trivy-json":
            finding_count = str(_count_trivy_artifact_findings(artifact.get("content", {})))
        artifact_table.add_row(
            _TYPE_KO.get(artifact_type, artifact_type),
            target,
            str(artifact.get("hash", ""))[:12],
            finding_count,
        )
    console.print(artifact_table)


def _count_trivy_artifact_findings(content: dict) -> int:
    total = 0
    for result in content.get("Results", []):
        total += len(result.get("Misconfigurations", []) or [])
        total += len(result.get("Vulnerabilities", []) or [])
        total += len(result.get("Secrets", []) or [])
    return total


def _join_items(items: list[str]) -> str:
    if not items:
        return "-"
    return "\n".join(items)


def _print_upload_response(response: dict) -> None:
    console.print("[green]업로드 완료[/green]")
    console.print(f"스캔 ID: {response.get('scanId', 'unknown')}")
    if response.get("viewUrl"):
        console.print(f"결과 보기: {response['viewUrl']}")


def _upload_or_exit(path: Path, api_url: str | None) -> dict:
    try:
        return upload_last_scan(path, api_url=api_url)
    except httpx.HTTPStatusError as exc:
        console.print(f"[red]업로드 실패:[/red] 서버가 {exc.response.status_code} 오류를 반환했습니다.")
    except httpx.HTTPError as exc:
        console.print(f"[red]업로드 실패:[/red] {exc}")
    except RuntimeError as exc:
        console.print(f"[red]업로드 실패:[/red] {exc}")
    raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
