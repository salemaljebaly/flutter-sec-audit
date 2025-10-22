"""
Command-line interface for FlutterSecAudit
"""
import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from pathlib import Path
import json
from datetime import datetime

from .extractors import APKExtractor, IPAExtractor
from .scanners import EnvScanner, AssetScanner, StringScanner
from .analyzers import SecurityScorer, AttackSimulator
from .models import AnalysisResult, Platform, Severity
from .reporters import HTMLReporter, JSONReporter, MarkdownReporter

console = Console()


@click.group()
@click.version_option(version="0.1.0")
def main():
    """
    FlutterSecAudit - Security scanner for Flutter apps

    Automated security analysis with attack simulation and detailed remediation.
    """
    pass


@main.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file path for report')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown', 'terminal']),
              default='terminal', help='Report format')
@click.option('--attack-sim', type=click.Choice(['beginner', 'intermediate', 'advanced']),
              help='Simulate attack at this level')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium']),
              help='Exit with error code if issues found at this severity')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def scan(file_path: str, output: str, format: str, attack_sim: str, fail_on: str, verbose: bool):
    """Scan APK or IPA file for security vulnerabilities"""

    try:
        # Display header
        console.print("\n")
        console.print(Panel.fit(
            "[bold cyan]FlutterSecAudit[/bold cyan] - Security Scanner",
            subtitle="v0.1.0"
        ))
        console.print()

        # Detect platform
        file_path_obj = Path(file_path)
        if file_path_obj.suffix.lower() == '.apk':
            platform = Platform.ANDROID
            extractor_class = APKExtractor
        elif file_path_obj.suffix.lower() == '.ipa':
            platform = Platform.IOS
            extractor_class = IPAExtractor
        else:
            console.print("[red]✗[/red] Unsupported file type. Please provide .apk or .ipa file")
            raise click.Abort()

        console.print(f"[cyan]→[/cyan] Platform: [bold]{platform.value}[/bold]")
        console.print(f"[cyan]→[/cyan] File: [bold]{file_path_obj.name}[/bold]")
        console.print()

        # Perform analysis with progress indicator
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:

            # Extract
            task = progress.add_task("[cyan]Extracting app...", total=None)
            extractor = extractor_class(file_path)
            extract_dir = extractor.extract()

            if not extractor.detect_flutter():
                console.print("[yellow]⚠[/yellow] Warning: This doesn't appear to be a Flutter app")

            progress.update(task, completed=True)

            # Initialize result
            app_name = extractor.app_name or file_path_obj.stem
            if platform == Platform.ANDROID:
                package_name = extractor.package_name or "unknown"
            else:  # iOS
                package_name = extractor.bundle_id or "unknown"

            result = AnalysisResult(
                app_name=app_name,
                package_name=package_name,
                platform=platform,
                file_path=file_path
            )

            # Run scanners
            task = progress.add_task("[cyan]Scanning for vulnerabilities...", total=None)

            # .env scanner
            env_scanner = EnvScanner()
            env_findings = env_scanner.scan(extract_dir)
            for finding in env_findings:
                result.add_finding(finding)

            # Asset scanner
            asset_scanner = AssetScanner()
            asset_findings = asset_scanner.scan(extract_dir)
            for finding in asset_findings:
                result.add_finding(finding)

            # String scanner
            string_scanner = StringScanner()
            string_findings = string_scanner.scan(extract_dir, platform.value.lower())
            for finding in string_findings:
                result.add_finding(finding)

            progress.update(task, completed=True)

            # Calculate scores
            task = progress.add_task("[cyan]Calculating security score...", total=None)
            scorer = SecurityScorer()
            result.security_score = scorer.calculate_score(result.findings)
            result.grade = scorer.get_grade(result.security_score)
            result.attack_surface_score = scorer.calculate_attack_surface(result.findings)
            progress.update(task, completed=True)

            # Attack simulation
            if attack_sim or len(result.findings) > 0:
                task = progress.add_task("[cyan]Simulating attacks...", total=None)
                simulator = AttackSimulator()
                attack_result = simulator.simulate_attack(result.findings)
                result.time_to_compromise_minutes = attack_result['overall_time_to_compromise']
                result.attacker_profile = attack_result['profiles'][attack_result['most_likely_attacker']]['profile']
                progress.update(task, completed=True)

            # Cleanup
            extractor.cleanup()

        # Display results
        _display_results(result, verbose)

        # Attack simulation details
        if attack_sim and result.findings:
            _display_attack_simulation(result, attack_result)

        # Generate report
        if output:
            _generate_report(result, output, format, attack_result if attack_sim else None)

        # Exit code handling
        if fail_on:
            severity_map = {
                'critical': Severity.CRITICAL,
                'high': Severity.HIGH,
                'medium': Severity.MEDIUM
            }

            counts = result.count_by_severity()
            if counts.get(severity_map[fail_on].value, 0) > 0:
                console.print(f"\n[red]✗[/red] Build failed: Found {fail_on} severity issues")
                raise click.Abort()

        console.print("\n[green]✓[/green] Scan completed successfully\n")

    except Exception as e:
        console.print(f"\n[red]✗ Error:[/red] {str(e)}\n")
        if verbose:
            console.print_exception()
        raise click.Abort()


def _display_results(result: AnalysisResult, verbose: bool):
    """Display scan results in terminal"""
    console.print()

    # Security Score Panel
    score_color = "green" if result.security_score >= 75 else "yellow" if result.security_score >= 50 else "red"
    console.print(Panel(
        f"[bold {score_color}]{result.security_score}/100[/bold {score_color}] - {result.grade}",
        title="Security Score",
        border_style=score_color
    ))
    console.print()

    # Findings Summary
    counts = result.count_by_severity()

    table = Table(title="Findings Summary", box=box.ROUNDED)
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Status", justify="center")

    severity_data = [
        ("CRITICAL", counts.get('CRITICAL', 0), "red"),
        ("HIGH", counts.get('HIGH', 0), "orange1"),
        ("MEDIUM", counts.get('MEDIUM', 0), "yellow"),
        ("LOW", counts.get('LOW', 0), "blue"),
    ]

    for severity, count, color in severity_data:
        status = "✗" if count > 0 else "✓"
        status_color = color if count > 0 else "green"
        table.add_row(
            f"[{color}]{severity}[/{color}]",
            f"[{color}]{count}[/{color}]",
            f"[{status_color}]{status}[/{status_color}]"
        )

    console.print(table)
    console.print()

    # Top Findings
    if result.findings:
        console.print("[bold]Top Priority Issues:[/bold]\n")

        scorer = SecurityScorer()
        top_findings = scorer.get_priority_findings(result.findings, 5)

        for i, finding in enumerate(top_findings, 1):
            severity_colors = {
                Severity.CRITICAL: "red",
                Severity.HIGH: "orange1",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue"
            }
            color = severity_colors.get(finding.severity, "white")

            console.print(f"  [{color}]{i}. [{finding.severity.value}] {finding.title}[/{color}]")
            if verbose and finding.remediation:
                console.print(f"     Fix: {finding.remediation.summary}")

        console.print()


def _display_attack_simulation(result: AnalysisResult, attack_result: dict):
    """Display attack simulation results"""
    console.print("\n[bold]Attack Simulation Results:[/bold]\n")

    most_likely = attack_result['most_likely_attacker']
    profile = attack_result['profiles'][most_likely]['profile']
    time_min = attack_result['overall_time_to_compromise']

    console.print(Panel(
        f"[bold red]Time to Compromise: {time_min} minutes[/bold red]\n"
        f"Most Likely Attacker: {profile.level}\n"
        f"Success Rate: {int(profile.success_rate * 100)}%",
        title="Threat Assessment",
        border_style="red"
    ))

    console.print("\n[bold]Attack Scenario:[/bold]\n")
    for step in attack_result['attack_scenario']:
        console.print(f"  {step}")
    console.print()


def _generate_report(result: AnalysisResult, output_path: str, format_type: str, attack_result: dict):
    """Generate report file"""
    with Progress(console=console) as progress:
        task = progress.add_task(f"[cyan]Generating {format_type} report...", total=None)

        if format_type == 'html':
            reporter = HTMLReporter()
            reporter.generate(result, output_path, attack_result)
        elif format_type == 'json':
            reporter = JSONReporter()
            reporter.generate(result, output_path, attack_result)
        elif format_type == 'markdown':
            reporter = MarkdownReporter()
            reporter.generate(result, output_path, attack_result)

        progress.update(task, completed=True)

    console.print(f"[green]✓[/green] Report saved to: {output_path}")


@main.command()
@click.argument('before', type=click.Path(exists=True))
@click.argument('after', type=click.Path(exists=True))
def compare(before: str, after: str):
    """Compare security scores before and after fixes"""
    console.print("\n[bold]Security Score Comparison[/bold]\n")
    console.print("Feature coming soon...")
    console.print()


if __name__ == '__main__':
    main()
