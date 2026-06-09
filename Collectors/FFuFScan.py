#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
from html import escape as html_escape
import io
import json
import os
import re
import select
import shlex
import shutil
import subprocess
import sys
try:
    import termios
    import tty
except ImportError:  # pragma: no cover - non-POSIX fallback
    termios = None
    tty = None
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


KATANA_SUFFIX = "_Katana.txt"
PROGRESS_RE = re.compile(r"Progress:\s*\[(\d+)/(\d+)\]")
FFUF_JOB_RE = re.compile(r"Job\s*\[(\d+)/(\d+)\]")
SUBSCAN_RE = re.compile(r"FFUFScan subscan:\s*\[(\d+)/(\d+)\]\s+total=(\d+)")
ERRORS_RE = re.compile(r"Errors:\s*(\d+)")
PRIMARY_RESULT_EXTENSIONS = (".json", ".html", ".md", ".csv")
EXTRA_RESULT_EXTENSIONS = (".ejson", ".ecsv")


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def normalize_url(raw: str) -> str:
    """Normalize an HTTP(S) URL for origin grouping and ffuf seeding."""
    value = raw.strip()
    if not value or value.startswith("#"):
        raise ValueError("empty input")

    parsed = urlsplit(value)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("missing hostname")

    hostname = hostname.lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(str(exc)) from exc

    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None

    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if port is None else f"{host}:{port}"
    path = parsed.path or "/"
    while "//" in path[1:]:
        path = path.replace("//", "/")
    return urlunsplit((scheme, netloc, path, "", ""))


def origin_from_url(url: str) -> str:
    """Return a normalized origin URL for a seed URL."""
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    hostname = parsed.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = host if parsed.port is None else f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, "/", "", ""))


def job_name_from_origin(origin: str) -> str:
    """Convert an origin into a stable job directory name."""
    parsed = urlsplit(origin)
    hostname = (parsed.hostname or "unknown").replace(":", "_")
    port_suffix = f"_{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}_{hostname}{port_suffix}"


def count_nonempty_lines(path: Path) -> int:
    """Count non-empty, non-comment lines in a file."""
    count = 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                count += 1
    return count


def sha256_file(path: Path) -> str:
    """Return a SHA-256 hex digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    """Return a SHA-256 hex digest for text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def relpath_or_absolute(base: Path, target: Path) -> str:
    """Return a base-relative path when possible, otherwise an absolute one."""
    try:
        return str(target.relative_to(base))
    except ValueError:
        return str(target)


def read_result_count(result_json: Path) -> int | None:
    """Return the number of ffuf matches from result.json when readable."""
    if not result_json.exists():
        return None
    try:
        data = json.loads(result_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    results = data.get("results")
    if isinstance(results, list):
        return len(results)
    return 0


def tail_lines(path: Path, limit: int = 10) -> list[str]:
    """Return the last non-empty lines of a text file."""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    nonempty = [line for line in lines if line.strip()]
    return nonempty[-limit:]


def ffuf_display_progress(
    current: int,
    total: int,
    ffuf_job_current: int | None,
    ffuf_job_total: int | None,
) -> tuple[int, int]:
    """Return progress adjusted for ffuf recursive internal Job [x/y] counters."""
    display_current = current
    display_total = total
    if (
        ffuf_job_current is not None
        and ffuf_job_total is not None
        and ffuf_job_current > 0
        and ffuf_job_total > 0
        and total > 0
    ):
        display_total = total * ffuf_job_total
        display_current = ((ffuf_job_current - 1) * total) + current
    return max(0, display_current), max(0, display_total)


def ensure_int_list_size(values: list[int], size: int, default: int) -> None:
    """Extend an int list to the requested size."""
    while len(values) < size:
        values.append(default)


def subscan_aggregate_progress(
    subscan_totals: list[int],
    subscan_index: int,
    current: int,
    total: int,
) -> tuple[int, int]:
    """Return progress adjusted for sequential FFuFScan subscans."""
    if not subscan_totals:
        return current, total
    subscan_index = max(0, min(subscan_index, len(subscan_totals) - 1))
    subscan_totals[subscan_index] = max(subscan_totals[subscan_index], total)
    done = sum(subscan_totals[:subscan_index]) + min(current, subscan_totals[subscan_index])
    return done, sum(subscan_totals)


def parse_ffuf_stderr_diagnostics(text: str) -> dict[str, int | None]:
    """Return the last ffuf progress and error counters from stderr text."""
    diagnostics: dict[str, int | None] = {
        "progress_done": None,
        "progress_total": None,
        "errors": None,
        "ffuf_job_current": None,
        "ffuf_job_total": None,
        "subscan_current": None,
        "subscan_total": None,
    }
    ffuf_job_current: int | None = None
    ffuf_job_total: int | None = None
    subscan_index = 0
    subscan_totals: list[int] = []
    normalized = text.replace("\r", "\n")
    for line in normalized.splitlines():
        subscan_match = SUBSCAN_RE.search(line)
        if subscan_match:
            subscan_current = int(subscan_match.group(1))
            subscan_total = int(subscan_match.group(2))
            subscan_estimate = int(subscan_match.group(3))
            ensure_int_list_size(subscan_totals, subscan_total, subscan_estimate)
            subscan_index = max(0, min(subscan_current - 1, len(subscan_totals) - 1))
            subscan_totals[subscan_index] = max(subscan_totals[subscan_index], subscan_estimate)
            diagnostics["subscan_current"] = subscan_current
            diagnostics["subscan_total"] = subscan_total
            ffuf_job_current = None
            ffuf_job_total = None

        job_match = FFUF_JOB_RE.search(line)
        if job_match:
            ffuf_job_current = int(job_match.group(1))
            ffuf_job_total = int(job_match.group(2))
            diagnostics["ffuf_job_current"] = ffuf_job_current
            diagnostics["ffuf_job_total"] = ffuf_job_total

        progress_match = PROGRESS_RE.search(line)
        if progress_match:
            current = int(progress_match.group(1))
            total = int(progress_match.group(2))
            display_current, display_total = ffuf_display_progress(
                current,
                total,
                ffuf_job_current,
                ffuf_job_total,
            )
            if subscan_totals:
                display_current, display_total = subscan_aggregate_progress(
                    subscan_totals,
                    subscan_index,
                    display_current,
                    display_total,
                )
            diagnostics["progress_done"] = display_current
            diagnostics["progress_total"] = display_total
        errors_match = ERRORS_RE.search(line)
        if errors_match:
            diagnostics["errors"] = int(errors_match.group(1))
    return diagnostics


def read_ffuf_stderr_diagnostics(path: Path) -> dict[str, int | None]:
    """Read ffuf stderr diagnostics, tolerating missing logs."""
    try:
        return parse_ffuf_stderr_diagnostics(path.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return {
            "progress_done": None,
            "progress_total": None,
            "errors": None,
            "ffuf_job_current": None,
            "ffuf_job_total": None,
            "subscan_current": None,
            "subscan_total": None,
        }


def build_job_hashes(seeds_file: Path, wordlist: Path, command_text: str) -> dict[str, str]:
    """Build the resume-relevant hashes for a job."""
    return {
        "paths_sha256": sha256_file(seeds_file),
        "wordlist_sha256": sha256_file(wordlist),
        "command_sha256": sha256_text(command_text),
    }


def load_resume_state(out_dir: Path, hashes: dict[str, str]) -> dict[str, object] | None:
    """Load a previous successful job state if it matches current inputs."""
    done_marker = out_dir / ".done"
    job_json = out_dir / "job.json"
    if not done_marker.exists() or not job_json.exists():
        return None

    for extension in PRIMARY_RESULT_EXTENSIONS:
        if not (out_dir / f"result{extension}").exists():
            return None

    try:
        state = json.loads(job_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if state.get("status") != "done":
        return None
    if state.get("hashes") != hashes:
        return None

    resumed_state = dict(state)
    resumed_state["status"] = "skipped"
    resumed_state["resumed"] = True
    result_count = read_result_count(out_dir / "result.json")
    if result_count is not None:
        resumed_state["result_count"] = result_count
    stderr_diagnostics = read_ffuf_stderr_diagnostics(out_dir / "ffuf.stderr.log")
    if stderr_diagnostics["progress_done"] is not None:
        resumed_state["ffuf_progress_done"] = stderr_diagnostics["progress_done"]
    if stderr_diagnostics["progress_total"] is not None:
        resumed_state["ffuf_progress_total"] = stderr_diagnostics["progress_total"]
    if stderr_diagnostics["errors"] is not None:
        resumed_state["ffuf_errors"] = stderr_diagnostics["errors"]
    paths_file = out_dir / "paths.txt"
    if paths_file.exists():
        resumed_state["seed_count"] = count_nonempty_lines(paths_file)
    return resumed_state


def estimate_total_requests(paths_file: Path, wordlist: Path, extensions: list[str] | None) -> int:
    """Estimate ffuf request count from path count, wordlist size, and extensions."""
    paths_count = count_nonempty_lines(paths_file)
    words_count = count_nonempty_lines(wordlist)
    multiplier = 1 + (len(extensions) if extensions else 0)
    return paths_count * words_count * multiplier


def estimate_single_seed_requests(wordlist: Path, extensions: list[str] | None) -> int:
    """Estimate ffuf request count for one direct -u <seed>FUZZ command."""
    words_count = count_nonempty_lines(wordlist)
    multiplier = 1 + (len(extensions) if extensions else 0)
    return words_count * multiplier


def format_job_line(
    idx: int,
    name: str,
    done: int,
    total: int,
    rate: float,
    state: str,
    elapsed_seconds: int,
    extra: str | None = None,
) -> str:
    """Return one compact status line for a running job."""
    total = max(total, 1)
    done = max(0, min(done, total))
    percent = int(done * 100 / total)
    remaining = max(0, total - done)
    eta_sec = int(remaining / rate) if rate > 0 else -1
    eta_text = "--:--" if eta_sec < 0 else f"{eta_sec // 60:02d}:{eta_sec % 60:02d}"
    elapsed_text = f"{elapsed_seconds // 60:02d}:{elapsed_seconds % 60:02d}"
    bar_width = 22
    filled = int(bar_width * done / total)
    bar = "#" * filled + "-" * (bar_width - filled)
    rate_text = "--/s" if rate <= 0 else f"{rate:.1f}/s"
    line = (
        f"  [{idx}] {name:<30} {state:<8} [{bar}] {percent:3d}%  "
        f"({done}/{total}) ETA {eta_text} Elapsed {elapsed_text} Rate {rate_text}"
    )
    if extra:
        line += f"  {extra}"
    return line


def print_job_line(
    idx: int,
    name: str,
    done: int,
    total: int,
    rate: float,
    state: str,
    elapsed_seconds: int,
) -> None:
    print(format_job_line(idx, name, done, total, rate, state, elapsed_seconds))


def running_job_display_state(job: FfufJob, now: float) -> tuple[str, str]:
    """Return a clearer state/heartbeat for a still-running ffuf process."""
    state = "running"
    parts: list[str] = []
    spinner = "|/-\\"[int(now * 4) % 4]

    if job.subscan_total_count > 1:
        parts.append(f"seed {job.active_subscan_index + 1}/{job.subscan_total_count}")
    if job.ffuf_job_current is not None and job.ffuf_job_total is not None:
        parts.append(f"ffuf job {job.ffuf_job_current}/{job.ffuf_job_total}")

    last_activity = job.last_stderr_activity or job.started or now
    idle_seconds = int(max(0.0, now - last_activity))
    progress_complete = job.saw_progress and job.done_est >= max(job.total, 1)
    if progress_complete:
        state = "recursing" if job_has_recursion(job) else "active"
        parts.append(f"alive {spinner}")
        parts.append(f"idle {idle_seconds}s")
    elif idle_seconds >= 5:
        parts.append(f"alive {spinner}")
        parts.append(f"idle {idle_seconds}s")

    return state, " ".join(parts)


def clear_lines(count: int) -> None:
    if count <= 0:
        return
    sys.stdout.write("\r")
    if count > 1:
        sys.stdout.write("\x1b[1F" * (count - 1))
    sys.stdout.write("\x1b[0J")
    sys.stdout.flush()


def dedupe_preserve_order(lines: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            output.append(line)
    return output


def read_seed_urls(path: Path) -> list[str]:
    """Read and normalize URL lines from a plain URL input file."""
    urls: list[str] = []
    seen: set[str] = set()

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            normalized = normalize_url(stripped)
        except ValueError as exc:
            print(
                f"Warning: skipping invalid URL on line {line_number}: {stripped} ({exc})",
                file=sys.stderr,
            )
            continue
        if normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)

    return urls


@dataclass
class JobSpec:
    name: str
    seed_urls: list[str]


def build_specs_from_url_file(path: Path) -> list[JobSpec]:
    """Build ffuf jobs by grouping a URL input file by origin."""
    grouped: dict[str, list[str]] = {}
    for url in read_seed_urls(path):
        grouped.setdefault(origin_from_url(url), []).append(url)

    return [
        JobSpec(name=job_name_from_origin(origin), seed_urls=dedupe_preserve_order(seed_urls))
        for origin, seed_urls in grouped.items()
    ]


def read_paths_file(path: Path) -> list[str]:
    """Read and normalize seed URLs from a Katana paths file."""
    urls: list[str] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            urls.append(normalize_url(stripped))
        except ValueError as exc:
            print(
                f"Warning: skipping invalid URL in {path.name}:{line_number}: {stripped} ({exc})",
                file=sys.stderr,
            )
    return dedupe_preserve_order(urls)


def build_specs_from_paths_dir(directory: Path) -> list[JobSpec]:
    """Build ffuf jobs from a Katana paths directory."""
    specs: list[JobSpec] = []
    for path_file in sorted(directory.glob(f"*{KATANA_SUFFIX}")):
        seed_urls = read_paths_file(path_file)
        if not seed_urls:
            continue
        name = path_file.name[: -len(KATANA_SUFFIX)] if path_file.name.endswith(KATANA_SUFFIX) else path_file.stem
        specs.append(JobSpec(name=name, seed_urls=seed_urls))
    return specs


def seed_slug(seed_url: str) -> str:
    """Return a compact filesystem-safe slug for a seed URL path."""
    try:
        parsed = urlsplit(seed_url)
    except ValueError:
        return sha256_text(seed_url)[:8]
    path = (parsed.path or "/").strip("/") or "root"
    if parsed.query:
        path += "_" + parsed.query
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", path).strip("_")
    return (slug or "root")[:60]


def build_ffuf_cmd(
    seeds_file: Path,
    wordlist: Path,
    out_dir: Path,
    rate: int,
    headers: list[str],
    proxy: str | None,
    extensions: list[str] | None,
    follow_redirects: bool,
    recursion_depth: int = 0,
    recursion_strategy: str = "default",
    base_url: str | None = None,
) -> list[str]:
    """Build an ffuf command for one job."""
    cmd = [
        "ffuf",
        "-c",
        "-noninteractive",
    ]
    if base_url:
        cmd += [
            "-w",
            f"{wordlist}:FUZZ",
            "-u",
            f"{base_url}FUZZ",
        ]
    else:
        cmd += [
            "-w",
            f"{seeds_file}:URL",
            "-w",
            f"{wordlist}:FUZZ",
            "-u",
            "URLFUZZ",
        ]
    cmd += [
        "-of",
        "all",
        "-o",
        str(out_dir / "result"),
        "-rate",
        str(rate),
    ]
    for header in headers:
        cmd += ["-H", header]
    if proxy:
        cmd += ["-x", proxy]
    if extensions:
        cmd += ["-e", ",".join(extensions)]
    if follow_redirects:
        cmd.append("-r")
    if recursion_depth > 0:
        cmd += [
            "-recursion",
            "-recursion-depth",
            str(recursion_depth),
            "-recursion-strategy",
            recursion_strategy,
        ]
    return cmd


def shell_lines(commands: list[list[str]]) -> list[str]:
    """Return shell-quoted command lines."""
    return [shlex.join(command) for command in commands]


def job_commands(job: "FfufJob") -> list[list[str]]:
    """Return all ffuf commands represented by a job."""
    if job.subscans:
        return [subscan.cmd for subscan in job.subscans]
    return [job.cmd]


def job_has_recursion(job: "FfufJob") -> bool:
    """Return whether a job command enables ffuf recursion."""
    return any("-recursion" in command for command in job_commands(job))


@dataclass
class FfufSubscan:
    index: int
    total: int
    seed_url: str
    out_dir: Path
    cmd: list[str]
    command_text: str
    estimated_total: int


@dataclass
class FfufJob:
    job_id: int
    name: str
    seeds_file: Path
    out_dir: Path
    total: int
    rate: int
    cmd: list[str]
    command_text: str
    hashes: dict[str, str]
    stderr_log: Path
    proc: subprocess.Popen | None = None
    started: float = 0.0
    done_est: int = 0
    finished: bool = False
    failed: bool = False
    retcode: int | None = None
    duration_seconds: float = 0.0
    result_count: int | None = None
    progress_offset: int = 0
    progress_remainder: str = ""
    saw_progress: bool = False
    progress_rate: float = 0.0
    last_progress_value: int = 0
    last_progress_time: float = 0.0
    last_display_progress_value: int = 0
    last_stderr_activity: float = 0.0
    ffuf_errors: int | None = None
    ffuf_progress_done: int | None = None
    ffuf_progress_total: int | None = None
    ffuf_job_current: int | None = None
    ffuf_job_total: int | None = None
    subscans: list[FfufSubscan] = field(default_factory=list)
    active_subscan_index: int = 0
    subscan_total_count: int = 1
    subscan_totals: list[int] = field(default_factory=list)
    stopped: bool = False
    stop_reason: str | None = None
    stop_requested_at: float = 0.0
    stop_aliases: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class StopRequest:
    raw: str
    job_id: int | None = None
    token: str | None = None


def normalize_stop_token(raw: str) -> str:
    """Normalize a manual stop token for exact case-insensitive matching."""
    value = raw.strip()
    if not value:
        return ""
    try:
        return normalize_url(value).lower()
    except ValueError:
        return value.rstrip("/").lower()


def build_stop_aliases(job_name: str, seed_urls: list[str]) -> set[str]:
    """Build exact aliases that can stop a job."""
    aliases = {normalize_stop_token(job_name)}
    for seed_url in seed_urls:
        try:
            origin = origin_from_url(seed_url)
        except ValueError:
            continue
        parsed = urlsplit(origin)
        aliases.add(origin.lower())
        aliases.add(origin.rstrip("/").lower())
        if parsed.netloc:
            aliases.add(parsed.netloc.lower())
        if parsed.hostname:
            aliases.add(parsed.hostname.lower())
    return {alias for alias in aliases if alias}


def build_stop_request(raw: str) -> StopRequest | None:
    """Build an exact-match stop request from an interactive target."""
    value = raw.strip()
    if not value:
        return None
    if value.isdigit():
        return StopRequest(raw=value, job_id=int(value))
    token = normalize_stop_token(value)
    if not token:
        return None
    return StopRequest(raw=value, token=token)


def format_stop_request(request: StopRequest) -> str:
    """Return a user-facing stop request label."""
    if request.job_id is not None:
        return f"#{request.job_id}"
    return request.token or request.raw


def job_matches_stop_request(job: FfufJob, request: StopRequest) -> bool:
    """Return True when a stop request exactly matches a job ID or alias."""
    if request.job_id is not None:
        return job.job_id == request.job_id
    if not request.token:
        return False
    aliases = job.stop_aliases or {normalize_stop_token(job.name)}
    return request.token in aliases


def describe_jobs(running: list[FfufJob], waiting: list[FfufJob]) -> list[str]:
    """Return compact running/waiting job descriptions for interactive output."""
    lines: list[str] = []
    if running:
        lines.append("Running: " + ", ".join(f"#{job.job_id} {job.name}" for job in running))
    else:
        lines.append("Running: -")
    if waiting:
        lines.append("Waiting: " + ", ".join(f"#{job.job_id} {job.name}" for job in waiting[:10]))
        if len(waiting) > 10:
            lines.append(f"Waiting: ... {len(waiting) - 10} more")
    else:
        lines.append("Waiting: -")
    return lines


def handle_interactive_command(
    raw_command: str,
    stop_requests: list[StopRequest],
    running: list[FfufJob],
    waiting: list[FfufJob],
) -> tuple[StopRequest | None, list[str]]:
    """Parse one interactive control command."""
    command = raw_command.strip()
    if not command:
        return None, []
    lowered = command.lower()
    if lowered in {"help", "h", "?"}:
        return None, ["Commands: s <id|host|job>, stop <id|host|job>, jobs, stops, help"]
    if lowered in {"jobs", "j"}:
        return None, describe_jobs(running=running, waiting=waiting)
    if lowered == "stops":
        labels = ", ".join(format_stop_request(request) for request in stop_requests) if stop_requests else "-"
        return None, [f"Stop requests: {labels}"]
    if lowered.startswith("stop "):
        request = build_stop_request(command[5:])
        if request is None:
            return None, ["Usage: stop <id|host|job>"]
        return request, [f"Stop requested: {format_stop_request(request)}"]
    if lowered.startswith("s "):
        request = build_stop_request(command[2:])
        if request is None:
            return None, ["Usage: s <id|host|job>"]
        return request, [f"Stop requested: {format_stop_request(request)}"]
    return None, [f"Unknown command: {command}"]


class InteractiveConsole:
    """Small no-echo command console rendered inside the live status table."""

    def __init__(self, enabled: bool | None = None) -> None:
        default_enabled = (
            termios is not None
            and tty is not None
            and sys.stdin.isatty()
            and sys.stdout.isatty()
        )
        self.enabled = default_enabled if enabled is None else enabled
        self.buffer = ""
        self._fd = sys.stdin.fileno() if self.enabled else -1
        self._old_attrs: list[object] | None = None
        self._escape_sequence = False

    def start(self) -> None:
        if not self.enabled or termios is None or tty is None:
            return
        try:
            self._old_attrs = termios.tcgetattr(self._fd)
            tty.setcbreak(self._fd)
            current_attrs = termios.tcgetattr(self._fd)
            current_attrs[3] = current_attrs[3] & ~termios.ECHO
            termios.tcsetattr(self._fd, termios.TCSADRAIN, current_attrs)
        except (OSError, termios.error):
            self.enabled = False
            self._old_attrs = None

    def stop(self) -> None:
        if self._old_attrs is None or termios is None:
            return
        try:
            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._old_attrs)
        except (OSError, termios.error):
            pass
        finally:
            self._old_attrs = None

    def feed_text(self, text: str) -> list[str]:
        """Feed terminal text into the console and return completed commands."""
        commands: list[str] = []
        for char in text:
            if self._escape_sequence:
                if char.isalpha() or char == "~":
                    self._escape_sequence = False
                continue
            if char == "\x1b":
                self._escape_sequence = True
                continue
            if char == "\x03":
                raise KeyboardInterrupt
            if char in {"\r", "\n"}:
                command = self.buffer.strip()
                self.buffer = ""
                if command:
                    commands.append(command)
                continue
            if char in {"\x7f", "\b"}:
                self.buffer = self.buffer[:-1]
                continue
            if char == "\x15":
                self.buffer = ""
                continue
            if char == "\x04":
                continue
            if char.isprintable():
                self.buffer += char
        return commands

    def read_commands(self) -> list[str]:
        """Read available console commands without blocking the scan loop."""
        if not self.enabled:
            return []
        commands: list[str] = []
        try:
            ready, _, _ = select.select([sys.stdin], [], [], 0)
            while ready:
                chunk = os.read(self._fd, 4096)
                if not chunk:
                    break
                commands.extend(self.feed_text(chunk.decode("utf-8", errors="ignore")))
                ready, _, _ = select.select([sys.stdin], [], [], 0)
        except (OSError, ValueError):
            return commands
        return commands

    def prompt_line(self) -> str:
        """Return the prompt line to render under the live table."""
        line = f"cmd> {self.buffer}"
        width = max(20, shutil.get_terminal_size((120, 24)).columns)
        if len(line) > width:
            line = "..." + line[-(width - 3) :]
        return line


def stop_job(job: FfufJob, reason: str, terminate_timeout: float = 2.0) -> None:
    """Mark a job stopped and terminate its ffuf process when it is running."""
    if job.finished:
        return
    now = time.time()
    job.stopped = True
    job.failed = False
    job.finished = True
    job.stop_reason = reason
    job.stop_requested_at = now
    if job.started > 0:
        job.duration_seconds = max(0.0, now - job.started)

    if job.proc and job.proc.poll() is None:
        try:
            job.proc.terminate()
        except OSError:
            pass
        try:
            job.proc.wait(timeout=terminate_timeout)
        except subprocess.TimeoutExpired:
            try:
                job.proc.kill()
            except OSError:
                pass
            try:
                job.proc.wait(timeout=terminate_timeout)
            except subprocess.TimeoutExpired:
                pass

    if job.proc:
        job.retcode = job.proc.returncode
    aggregate_recursive_subscan_outputs(job)
    job.result_count = read_result_count(job.out_dir / "result.json")


def apply_stop_requests(
    running: list[FfufJob],
    waiting: list[FfufJob],
    finished: list[FfufJob],
    stopped_jobs: list[FfufJob],
    stop_requests: list[StopRequest],
) -> list[str]:
    """Stop running/waiting jobs that match requested stop requests."""
    messages: list[str] = []
    if not stop_requests:
        return messages

    for job in list(running):
        matched = next((request for request in stop_requests if job_matches_stop_request(job, request)), None)
        if matched is None:
            continue
        matched_label = format_stop_request(matched)
        stop_job(job, reason=f"manual stop matched: {matched_label}")
        running.remove(job)
        finished.append(job)
        stopped_jobs.append(job)
        messages.append(f"Stopped running job #{job.job_id} {job.name} ({matched_label})")

    for job in list(waiting):
        matched = next((request for request in stop_requests if job_matches_stop_request(job, request)), None)
        if matched is None:
            continue
        matched_label = format_stop_request(matched)
        stop_job(job, reason=f"manual stop before start matched: {matched_label}")
        waiting.remove(job)
        finished.append(job)
        stopped_jobs.append(job)
        messages.append(f"Stopped waiting job #{job.job_id} {job.name} ({matched_label})")

    return messages


def active_subscan(job: FfufJob) -> FfufSubscan | None:
    """Return the active sequential subscan for a job."""
    if not job.subscans:
        return None
    if job.active_subscan_index < 0 or job.active_subscan_index >= len(job.subscans):
        return None
    return job.subscans[job.active_subscan_index]


def write_subscan_marker(stderr_handle: io.TextIOBase, subscan: FfufSubscan) -> None:
    """Write a parseable FFuFScan marker before a sequential subscan starts."""
    stderr_handle.write(
        f"FFUFScan subscan: [{subscan.index}/{subscan.total}] "
        f"total={subscan.estimated_total} seed={subscan.seed_url}\n"
    )
    stderr_handle.flush()


def start_active_ffuf_process(job: FfufJob, truncate_log: bool) -> None:
    """Start the active ffuf process for a job or subscan."""
    current_subscan = active_subscan(job)
    cmd = current_subscan.cmd if current_subscan is not None else job.cmd
    job.cmd = cmd
    job.ffuf_job_current = None
    job.ffuf_job_total = None
    job.ffuf_progress_done = None
    job.ffuf_progress_total = None
    now = time.time()
    job.last_stderr_activity = now
    stderr_handle = job.stderr_log.open("w" if truncate_log else "a", encoding="utf-8")
    if current_subscan is not None:
        write_subscan_marker(stderr_handle, current_subscan)
    job.proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=stderr_handle,
        text=True,
    )
    stderr_handle.close()


def run_ffuf_background(job: FfufJob) -> None:
    """Start ffuf for one job in the background."""
    job.started = time.time()
    job.active_subscan_index = 0
    start_active_ffuf_process(job, truncate_log=True)


def update_job_progress_from_stderr(job: FfufJob) -> bool:
    """Parse ffuf stderr progress lines like 'Progress: [12/100]'."""
    if not job.stderr_log.exists():
        return False

    try:
        with job.stderr_log.open("rb") as handle:
            handle.seek(job.progress_offset)
            chunk = handle.read()
    except OSError:
        return False

    if not chunk:
        return True

    job.last_stderr_activity = time.time()
    job.progress_offset += len(chunk)
    text = chunk.decode("utf-8", errors="ignore").replace("\r", "\n")
    combined = job.progress_remainder + text
    lines = combined.split("\n")

    if combined and not combined.endswith("\n"):
        job.progress_remainder = lines.pop()
    else:
        job.progress_remainder = ""

    for line in lines:
        subscan_match = SUBSCAN_RE.search(line)
        if subscan_match:
            subscan_current = int(subscan_match.group(1))
            subscan_total = int(subscan_match.group(2))
            subscan_estimate = int(subscan_match.group(3))
            job.subscan_total_count = max(1, subscan_total)
            ensure_int_list_size(job.subscan_totals, subscan_total, subscan_estimate)
            job.active_subscan_index = max(0, min(subscan_current - 1, len(job.subscan_totals) - 1))
            job.subscan_totals[job.active_subscan_index] = max(
                job.subscan_totals[job.active_subscan_index],
                subscan_estimate,
            )
            job.total = max(job.total, sum(job.subscan_totals))
            job.ffuf_job_current = None
            job.ffuf_job_total = None

        job_match = FFUF_JOB_RE.search(line)
        if job_match:
            job.ffuf_job_current = int(job_match.group(1))
            job.ffuf_job_total = int(job_match.group(2))

        match = PROGRESS_RE.search(line)
        if match:
            now = time.time()
            current = int(match.group(1))
            total = int(match.group(2))
            job.ffuf_progress_done = current
            job.ffuf_progress_total = total
            if total > 0:
                display_current, display_total = ffuf_display_progress(
                    current,
                    total,
                    job.ffuf_job_current,
                    job.ffuf_job_total,
                )
                if job.subscan_totals:
                    display_current, display_total = subscan_aggregate_progress(
                        job.subscan_totals,
                        job.active_subscan_index,
                        display_current,
                        display_total,
                    )
                job.ffuf_progress_done = display_current
                job.ffuf_progress_total = display_total
                job.total = display_total
                job.done_est = max(0, min(display_current, display_total))
                job.saw_progress = True
            progress_value = job.done_est
            if progress_value > job.last_display_progress_value:
                if job.last_progress_time > 0:
                    delta_time = now - job.last_progress_time
                    if delta_time > 0:
                        job.progress_rate = (progress_value - job.last_display_progress_value) / delta_time
                job.last_display_progress_value = progress_value
                job.last_progress_value = current
                job.last_progress_time = now

        errors_match = ERRORS_RE.search(line)
        if errors_match:
            job.ffuf_errors = int(errors_match.group(1))

    return True


def reap_job(job: FfufJob) -> None:
    """Update job completion state from the child process."""
    if job.finished or not job.proc:
        return
    retcode = job.proc.poll()
    if retcode is None:
        return
    if retcode == 0 and job.subscans and job.active_subscan_index + 1 < len(job.subscans):
        if job.subscan_totals:
            completed_index = max(0, min(job.active_subscan_index, len(job.subscan_totals) - 1))
            job.done_est = min(sum(job.subscan_totals[: completed_index + 1]), max(job.total, 1))
        job.active_subscan_index += 1
        job.proc = None
        start_active_ffuf_process(job, truncate_log=False)
        return

    job.retcode = retcode
    job.finished = True
    job.failed = retcode != 0
    job.duration_seconds = max(0.0, time.time() - job.started)
    if job.subscans:
        aggregate_recursive_subscan_outputs(job)
    job.result_count = read_result_count(job.out_dir / "result.json")
    if not job.failed:
        job.done_est = job.total


def cleanup_ffuf_outputs(out_dir: Path) -> None:
    """Keep result.json/html/md/csv, remove only extra ffuf sidecar formats."""
    for ext in EXTRA_RESULT_EXTENSIONS:
        candidate = out_dir / f"result{ext}"
        if candidate.exists():
            try:
                candidate.unlink()
            except OSError:
                pass


def job_seed_count(job: FfufJob) -> int | None:
    """Return the number of seed URLs for a job when paths.txt is readable."""
    try:
        return count_nonempty_lines(job.seeds_file)
    except OSError:
        return None


def build_job_summary(job: FfufJob, output_root: Path, status: str | None = None, resumed: bool = False) -> dict[str, object]:
    """Build a serializable per-job summary."""
    actual_status = status or ("stopped" if job.stopped else "failed" if job.failed else "done")
    stderr_diagnostics = read_ffuf_stderr_diagnostics(job.stderr_log)
    progress_done = stderr_diagnostics["progress_done"]
    progress_total = stderr_diagnostics["progress_total"]
    errors = stderr_diagnostics["errors"]
    if progress_done is None:
        progress_done = job.ffuf_progress_done
    if progress_total is None:
        progress_total = job.ffuf_progress_total
    if errors is None:
        errors = job.ffuf_errors
    outputs = {
        "json": relpath_or_absolute(output_root, job.out_dir / "result.json"),
        "html": relpath_or_absolute(output_root, job.out_dir / "result.html"),
        "md": relpath_or_absolute(output_root, job.out_dir / "result.md"),
        "csv": relpath_or_absolute(output_root, job.out_dir / "result.csv"),
        "stderr_log": relpath_or_absolute(output_root, job.stderr_log),
        "command": relpath_or_absolute(output_root, job.out_dir / "command.txt"),
    }
    return {
        "job_id": job.job_id,
        "name": job.name,
        "status": actual_status,
        "resumed": resumed,
        "exit_code": job.retcode,
        "duration_seconds": round(job.duration_seconds, 3),
        "result_count": job.result_count,
        "seed_count": job_seed_count(job),
        "ffuf_progress_done": progress_done,
        "ffuf_progress_total": progress_total,
        "ffuf_errors": errors,
        "paths_file": relpath_or_absolute(output_root, job.seeds_file),
        "outputs": outputs,
        "hashes": job.hashes,
        "command": job.command_text,
        "stop_reason": job.stop_reason,
        "stop_requested_at": None if job.stop_requested_at <= 0 else round(job.stop_requested_at, 3),
    }


def write_job_state(job: FfufJob, output_root: Path, status: str | None = None, resumed: bool = False) -> dict[str, object]:
    """Persist per-job state to job.json and update the done marker."""
    summary = build_job_summary(job, output_root=output_root, status=status, resumed=resumed)
    job_json = job.out_dir / "job.json"
    done_marker = job.out_dir / ".done"
    job_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if summary["status"] == "done":
        done_marker.write_text("done\n", encoding="utf-8")
    elif done_marker.exists():
        try:
            done_marker.unlink()
        except OSError:
            pass
    return summary


def write_index_files(output_root: Path, summaries: list[dict[str, object]]) -> None:
    """Write ffuf/index.json and ffuf/index.md."""
    ordered = sorted(summaries, key=lambda item: str(item.get("name", "")))
    index_json = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "output_dir": str(output_root),
        "jobs": ordered,
    }
    (output_root / "index.json").write_text(
        json.dumps(index_json, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# FFUF Summary",
        "",
        "| Job | Status | Hits | Seeds | Progress | Errors | Exit | Duration | JSON | HTML | MD | CSV |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- | --- | --- |",
    ]
    for item in ordered:
        outputs = item.get("outputs", {})
        outputs = outputs if isinstance(outputs, dict) else {}
        hits = item.get("result_count")
        hits_text = "-" if hits is None else str(hits)
        seed_count = item.get("seed_count")
        seed_text = "-" if seed_count is None else str(seed_count)
        progress_done = item.get("ffuf_progress_done")
        progress_total = item.get("ffuf_progress_total")
        progress_text = "-"
        if progress_done is not None and progress_total is not None:
            progress_text = f"{progress_done}/{progress_total}"
        errors = item.get("ffuf_errors")
        errors_text = "-" if errors is None else str(errors)
        exit_code = item.get("exit_code")
        exit_text = "-" if exit_code is None else str(exit_code)
        duration = item.get("duration_seconds")
        duration_text = "-" if duration is None else str(duration)
        lines.append(
            (
                "| {job} | {status} | {hits} | {seeds} | {progress} | {errors} | {exit_code} | {duration} | "
                "{json_path} | {html_path} | {md_path} | {csv_path} |"
            ).format(
                job=item.get("name", "-"),
                status=item.get("status", "-"),
                hits=hits_text,
                seeds=seed_text,
                progress=progress_text,
                errors=errors_text,
                exit_code=exit_text,
                duration=duration_text,
                json_path=outputs.get("json", "-"),
                html_path=outputs.get("html", "-"),
                md_path=outputs.get("md", "-"),
                csv_path=outputs.get("csv", "-"),
            )
        )
    (output_root / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def scalar_text(value: object) -> str:
    """Render a JSON scalar safely for reports."""
    if value is None or value == "":
        return "-"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def result_value(item: dict[str, object], *keys: str) -> object:
    """Return the first present value for a ffuf result field."""
    for key in keys:
        if key in item:
            return item[key]
    return None


def result_input_value(item: dict[str, object], *keys: str) -> object:
    """Return a value from ffuf's nested input object or top-level fallback."""
    input_value = item.get("input")
    candidates: list[str] = []
    for key in keys:
        candidates.extend([key, key.upper(), key.lower()])
    if isinstance(input_value, dict):
        for key in candidates:
            if key in input_value:
                return input_value[key]
    for key in candidates:
        if key in item:
            return item[key]
    return None


def scalar_or_none(value: object) -> str | None:
    """Render a non-empty scalar, returning None for absent values."""
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def result_url(item: dict[str, object]) -> str:
    """Return the result URL, rebuilding URLFUZZ from ffuf input data when needed."""
    direct = scalar_or_none(result_value(item, "url", "Url"))
    if direct:
        return direct

    base = scalar_or_none(result_input_value(item, "URL"))
    fuzz = scalar_or_none(result_input_value(item, "FUZZ"))
    if base and fuzz:
        return base + fuzz
    if base:
        return base
    return "-"


def host_from_result(url: str, fallback: str) -> str:
    """Return the result URL host/netloc, or a job-name fallback."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return fallback
    if parsed.netloc:
        return parsed.netloc.lower()
    return fallback


def path_from_result_url(url: str) -> str:
    """Return a compact path+query view for a result URL."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url or "-"
    if not parsed.path and not parsed.query:
        return parsed.geturl() or "-"
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    return path


def summary_result_json_path(output_root: Path, summary: dict[str, object]) -> Path | None:
    """Resolve the result.json path stored in a job summary."""
    outputs = summary.get("outputs", {})
    outputs = outputs if isinstance(outputs, dict) else {}
    raw_path = outputs.get("json")
    if isinstance(raw_path, str) and raw_path and raw_path != "-":
        path = Path(raw_path)
        return path if path.is_absolute() else output_root / path

    name = summary.get("name")
    if isinstance(name, str) and name:
        return output_root / name / "result.json"
    return None


@dataclass
class ResultJsonRead:
    path: Path | None
    state: str
    items: list[dict[str, object]] = field(default_factory=list)


def read_ffuf_result_json(result_json: Path | None) -> ResultJsonRead:
    """Read ffuf result.json and keep enough state for diagnostics."""
    if result_json is None:
        return ResultJsonRead(path=None, state="missing")
    if not result_json.exists():
        return ResultJsonRead(path=result_json, state="missing")
    try:
        data = json.loads(result_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ResultJsonRead(path=result_json, state="invalid")
    except OSError:
        return ResultJsonRead(path=result_json, state="unreadable")

    if not isinstance(data, dict):
        return ResultJsonRead(path=result_json, state="invalid")
    results = data.get("results")
    if not isinstance(results, list):
        return ResultJsonRead(path=result_json, state="invalid")
    items = [item for item in results if isinstance(item, dict)]
    if not items:
        return ResultJsonRead(path=result_json, state="empty")
    return ResultJsonRead(path=result_json, state="readable", items=items)


def read_ffuf_result_items(result_json: Path) -> list[dict[str, object]]:
    """Read ffuf result objects from result.json, tolerating missing or bad files."""
    return read_ffuf_result_json(result_json).items


def subscan_output_paths(job_root: Path, subscan: FfufSubscan) -> dict[str, str]:
    """Return job-root-relative subscan output paths."""
    return {
        "json": relpath_or_absolute(job_root, subscan.out_dir / "result.json"),
        "html": relpath_or_absolute(job_root, subscan.out_dir / "result.html"),
        "md": relpath_or_absolute(job_root, subscan.out_dir / "result.md"),
        "csv": relpath_or_absolute(job_root, subscan.out_dir / "result.csv"),
    }


def aggregate_recursive_subscan_outputs(job: FfufJob) -> None:
    """Build top-level result files from sequential recursive subscan outputs."""
    if not job.subscans:
        return

    aggregated_results: list[dict[str, object]] = []
    subscan_summaries: list[dict[str, object]] = []
    for subscan in job.subscans:
        result_json = subscan.out_dir / "result.json"
        read_result = read_ffuf_result_json(result_json)
        items = read_result.items if read_result.state in {"readable", "empty"} else []
        aggregated_results.extend(dict(item) for item in items)
        subscan_summaries.append(
            {
                "index": subscan.index,
                "total": subscan.total,
                "seed_url": subscan.seed_url,
                "state": read_result.state,
                "result_count": len(items),
                "outputs": subscan_output_paths(job.out_dir, subscan),
            }
        )

    aggregate_json = {
        "results": aggregated_results,
        "ffufscan": {
            "aggregated": True,
            "subscan_count": len(job.subscans),
            "subscans": subscan_summaries,
        },
    }
    (job.out_dir / "result.json").write_text(
        json.dumps(aggregate_json, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    html_lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>FFUF Recursive Subscans - {html_escape(job.name)}</title>",
        "<style>",
        "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 24px; color: #18202a; }",
        "table { border-collapse: collapse; width: 100%; }",
        "th, td { border: 1px solid #d9dee7; padding: 8px 10px; text-align: left; vertical-align: top; }",
        "th { background: #f3f5f8; }",
        "a { color: #1f6feb; text-decoration: none; }",
        "a:hover { text-decoration: underline; }",
        "</style>",
        "</head>",
        "<body>",
        f"<h1>FFUF Recursive Subscans - {html_escape(job.name)}</h1>",
        f"<p>Total subscans: {len(job.subscans)}. Aggregated results: {len(aggregated_results)}.</p>",
        "<table>",
        "<thead><tr><th>#</th><th>Seed URL</th><th>State</th><th>Hits</th><th>JSON</th><th>HTML</th><th>MD</th><th>CSV</th></tr></thead>",
        "<tbody>",
    ]
    for summary in subscan_summaries:
        outputs = summary["outputs"]
        outputs = outputs if isinstance(outputs, dict) else {}
        html_lines.append(
            "<tr>"
            f"<td>{html_escape(str(summary['index']))}</td>"
            f"<td>{html_escape(str(summary['seed_url']))}</td>"
            f"<td>{html_escape(str(summary['state']))}</td>"
            f"<td>{html_escape(str(summary['result_count']))}</td>"
            f"<td><a href=\"{html_escape(str(outputs.get('json', '-')), quote=True)}\">json</a></td>"
            f"<td><a href=\"{html_escape(str(outputs.get('html', '-')), quote=True)}\">html</a></td>"
            f"<td><a href=\"{html_escape(str(outputs.get('md', '-')), quote=True)}\">md</a></td>"
            f"<td><a href=\"{html_escape(str(outputs.get('csv', '-')), quote=True)}\">csv</a></td>"
            "</tr>"
        )
    html_lines += ["</tbody>", "</table>", "</body>", "</html>"]
    (job.out_dir / "result.html").write_text("\n".join(html_lines) + "\n", encoding="utf-8")

    md_lines = [
        "# FFUF Recursive Subscans",
        "",
        f"Job: {job.name}",
        f"Aggregated results: {len(aggregated_results)}",
        "",
        "| # | Seed URL | State | Hits | JSON | HTML | MD | CSV |",
        "| ---: | --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for summary in subscan_summaries:
        outputs = summary["outputs"]
        outputs = outputs if isinstance(outputs, dict) else {}
        md_lines.append(
            "| {index} | {seed} | {state} | {hits} | {json_path} | {html_path} | {md_path} | {csv_path} |".format(
                index=summary["index"],
                seed=summary["seed_url"],
                state=summary["state"],
                hits=summary["result_count"],
                json_path=outputs.get("json", "-"),
                html_path=outputs.get("html", "-"),
                md_path=outputs.get("md", "-"),
                csv_path=outputs.get("csv", "-"),
            )
        )
    (job.out_dir / "result.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(["subscan", "seed_url", "url", "status", "length", "words", "lines", "content-type", "redirectlocation"])
    for summary, subscan in zip(subscan_summaries, job.subscans):
        for item in read_ffuf_result_items(subscan.out_dir / "result.json"):
            writer.writerow(
                [
                    summary["index"],
                    subscan.seed_url,
                    result_url(item),
                    scalar_text(result_value(item, "status", "status_code", "StatusCode")),
                    scalar_text(result_value(item, "length", "size", "content_length", "ContentLength")),
                    scalar_text(result_value(item, "words", "content_words", "ContentWords")),
                    scalar_text(result_value(item, "lines", "content_lines", "ContentLines")),
                    scalar_text(result_value(item, "content-type", "content_type", "ContentType")),
                    scalar_text(result_value(item, "redirectlocation", "redirect", "RedirectLocation")),
                ]
            )
    (job.out_dir / "result.csv").write_text(csv_buffer.getvalue(), encoding="utf-8")


def collect_unique_result_rows(
    output_root: Path,
    summaries: list[dict[str, object]],
) -> dict[str, list[dict[str, str]]]:
    """Collect first ffuf result per host/status/size for manual review."""
    grouped: dict[str, list[dict[str, str]]] = {}
    seen_by_host: dict[str, set[tuple[str, str]]] = {}

    for summary in sorted(summaries, key=lambda item: str(item.get("name", ""))):
        result_json = summary_result_json_path(output_root, summary)
        if result_json is None:
            continue

        fallback_host = scalar_text(summary.get("name"))
        for item in read_ffuf_result_items(result_json):
            url = result_url(item)
            host = host_from_result(url, fallback_host)
            path = path_from_result_url(url)
            status = scalar_text(result_value(item, "status", "status_code", "StatusCode"))
            size = scalar_text(result_value(item, "length", "size", "content_length", "ContentLength"))
            key = (status, size)
            seen = seen_by_host.setdefault(host, set())
            if key in seen:
                continue
            seen.add(key)
            grouped.setdefault(host, []).append(
                {
                    "status": status,
                    "size": size,
                    "path": path,
                    "url": url,
                    "words": scalar_text(result_value(item, "words", "content_words", "ContentWords")),
                    "lines": scalar_text(result_value(item, "lines", "content_lines", "ContentLines")),
                    "content_type": scalar_text(result_value(item, "content-type", "content_type", "ContentType")),
                    "redirect": scalar_text(result_value(item, "redirectlocation", "redirect", "RedirectLocation")),
                }
            )

    return grouped


def write_unique_paths_html(output_root: Path, summaries: list[dict[str, object]]) -> None:
    """Write a self-contained HTML report with unique ffuf paths per host."""
    grouped = collect_unique_result_rows(output_root, summaries)
    total_rows = sum(len(rows) for rows in grouped.values())
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>FFUF Unique Paths</title>",
        "<style>",
        ":root { color-scheme: light; --bg: #f6f7f9; --panel: #ffffff; --text: #18202a; --muted: #687381; --line: #d9dee7; --accent: #1f6feb; }",
        "* { box-sizing: border-box; }",
        "body { margin: 0; background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.45; }",
        "main { width: min(1400px, calc(100% - 32px)); margin: 24px auto 40px; }",
        "header { margin-bottom: 18px; }",
        "h1 { margin: 0 0 6px; font-size: 28px; font-weight: 700; }",
        ".meta { color: var(--muted); display: flex; flex-wrap: wrap; gap: 12px; }",
        "section { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; margin-top: 16px; overflow: hidden; }",
        "h2 { margin: 0; padding: 12px 14px; font-size: 17px; background: #eef2f7; border-bottom: 1px solid var(--line); }",
        ".count { color: var(--muted); font-weight: 500; }",
        ".table-wrap { overflow-x: auto; }",
        "table { width: 100%; border-collapse: collapse; table-layout: fixed; }",
        "th, td { padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; text-align: left; }",
        "th { color: #344054; background: #fafbfc; font-size: 12px; text-transform: uppercase; letter-spacing: 0; }",
        "th.sortable { padding: 0; }",
        ".sort-btn { width: 100%; min-height: 36px; padding: 9px 10px; border: 0; background: transparent; color: inherit; font: inherit; text-transform: inherit; text-align: left; cursor: pointer; display: flex; align-items: center; gap: 6px; }",
        ".sort-btn:hover { background: #eef2f7; }",
        ".sort-mark { color: var(--accent); font-weight: 700; text-transform: none; }",
        ".reset-sort { margin-left: 10px; border: 1px solid var(--line); background: #fff; color: #344054; border-radius: 6px; padding: 4px 8px; cursor: pointer; font: inherit; font-size: 12px; }",
        ".reset-sort:hover { border-color: var(--accent); color: var(--accent); }",
        "tr:last-child td { border-bottom: 0; }",
        "a { color: var(--accent); text-decoration: none; }",
        "a:hover { text-decoration: underline; }",
        ".num { width: 90px; white-space: nowrap; }",
        ".path { width: 23%; overflow-wrap: anywhere; }",
        ".url { width: 33%; overflow-wrap: anywhere; }",
        ".small { width: 120px; overflow-wrap: anywhere; }",
        ".empty { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px; color: var(--muted); }",
        "</style>",
        "</head>",
        "<body>",
        "<main>",
        "<header>",
        "<h1>FFUF Unique Paths</h1>",
        (
            '<div class="meta">'
            f"<span>Generated: {html_escape(generated_at)}</span>"
            f"<span>Hosts: {len(grouped)}</span>"
            f"<span>Unique rows: {total_rows}</span>"
            "<span>Uniqueness: host + status + size</span>"
            "</div>"
        ),
        "</header>",
    ]

    if not grouped:
        lines.append('<div class="empty">No matched ffuf result URLs were found in result.json files.</div>')
    else:
        for host in sorted(grouped):
            rows = grouped[host]
            lines += [
                "<section>",
                f"<h2>{html_escape(host)} <span class=\"count\">({len(rows)})</span><button class=\"reset-sort\" type=\"button\">Reset sort</button></h2>",
                '<div class="table-wrap">',
                '<table data-host-table="1">',
                "<thead>",
                "<tr>",
                '<th class="url">URL</th>',
                '<th class="path">Path</th>',
                '<th class="num sortable"><button class="sort-btn" type="button" data-sort-key="status">Status <span class="sort-mark"></span></button></th>',
                '<th class="num sortable"><button class="sort-btn" type="button" data-sort-key="size">Size <span class="sort-mark"></span></button></th>',
                '<th class="num sortable"><button class="sort-btn" type="button" data-sort-key="words">Words <span class="sort-mark"></span></button></th>',
                '<th class="num">Lines</th>',
                '<th class="small">Redirect</th>',
                '<th class="small">Content-Type</th>',
                "</tr>",
                "</thead>",
                "<tbody>",
            ]
            for index, row in enumerate(rows):
                url = row["url"]
                url_cell = html_escape(url)
                if url != "-":
                    url_cell = f'<a href="{html_escape(url, quote=True)}" target="_blank" rel="noopener noreferrer">{url_cell}</a>'
                lines.append(
                    "<tr "
                    f'data-index="{index}" '
                    f'data-status="{html_escape(row["status"], quote=True)}" '
                    f'data-size="{html_escape(row["size"], quote=True)}" '
                    f'data-words="{html_escape(row["words"], quote=True)}">'
                    f'<td class="url">{url_cell}</td>'
                    f'<td class="path">{html_escape(row["path"])}</td>'
                    f'<td class="num">{html_escape(row["status"])}</td>'
                    f'<td class="num">{html_escape(row["size"])}</td>'
                    f'<td class="num">{html_escape(row["words"])}</td>'
                    f'<td class="num">{html_escape(row["lines"])}</td>'
                    f'<td class="small">{html_escape(row["redirect"])}</td>'
                    f'<td class="small">{html_escape(row["content_type"])}</td>'
                    "</tr>"
                )
            lines += [
                "</tbody>",
                "</table>",
                "</div>",
                "</section>",
            ]

    lines += [
        "</main>",
        "<script>",
        "(function () {",
        "  function readNumber(row, key) {",
        "    var raw = row.dataset[key] || '';",
        "    var value = Number(raw);",
        "    return Number.isFinite(value) ? value : null;",
        "  }",
        "  function compareRows(a, b, sorts) {",
        "    for (var i = 0; i < sorts.length; i += 1) {",
        "      var sort = sorts[i];",
        "      var av = readNumber(a, sort.key);",
        "      var bv = readNumber(b, sort.key);",
        "      if (av === null && bv === null) { continue; }",
        "      if (av === null) { return 1; }",
        "      if (bv === null) { return -1; }",
        "      if (av !== bv) { return sort.dir === 'asc' ? av - bv : bv - av; }",
        "    }",
        "    return Number(a.dataset.index || 0) - Number(b.dataset.index || 0);",
        "  }",
        "  function renderMarks(table, sorts) {",
        "    table.querySelectorAll('.sort-btn').forEach(function (button) {",
        "      var key = button.dataset.sortKey;",
        "      var mark = button.querySelector('.sort-mark');",
        "      var index = sorts.findIndex(function (item) { return item.key === key; });",
        "      mark.textContent = index === -1 ? '' : String(index + 1) + (sorts[index].dir === 'asc' ? ' up' : ' down');",
        "    });",
        "  }",
        "  function applySort(table) {",
        "    var sorts = table._ffufSorts || [];",
        "    var tbody = table.tBodies[0];",
        "    var rows = Array.prototype.slice.call(tbody.rows);",
        "    rows.sort(function (a, b) { return compareRows(a, b, sorts); });",
        "    rows.forEach(function (row) { tbody.appendChild(row); });",
        "    renderMarks(table, sorts);",
        "  }",
        "  document.querySelectorAll('table[data-host-table]').forEach(function (table) {",
        "    table._ffufSorts = [];",
        "    table.querySelectorAll('.sort-btn').forEach(function (button) {",
        "      button.addEventListener('click', function () {",
        "        var key = button.dataset.sortKey;",
        "        var sorts = table._ffufSorts;",
        "        var index = sorts.findIndex(function (item) { return item.key === key; });",
        "        if (index === -1) {",
        "          sorts.push({ key: key, dir: 'asc' });",
        "        } else if (sorts[index].dir === 'asc') {",
        "          sorts[index].dir = 'desc';",
        "        } else {",
        "          sorts.splice(index, 1);",
        "        }",
        "        applySort(table);",
        "      });",
        "    });",
        "    var reset = table.closest('section').querySelector('.reset-sort');",
        "    if (reset) {",
        "      reset.addEventListener('click', function () {",
        "        table._ffufSorts = [];",
        "        applySort(table);",
        "      });",
        "    }",
        "  });",
        "}());",
        "</script>",
        "</body>",
        "</html>",
    ]
    (output_root / "unique_paths.html").write_text("\n".join(lines) + "\n", encoding="utf-8")


def prepare_job(job_spec: JobSpec, args: argparse.Namespace, extensions: list[str] | None, job_id: int = 0) -> FfufJob:
    """Create job files and runtime metadata."""
    out_dir = args.output_dir / job_spec.name
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds_file = out_dir / "paths.txt"
    seeds_file.write_text("\n".join(job_spec.seed_urls) + "\n", encoding="utf-8")
    recursion_depth = getattr(args, "recursion_depth", 0)
    headers = getattr(args, "headers", None) or []
    recursion_strategy = getattr(args, "recursion_strategy", "default")
    subscans: list[FfufSubscan] = []

    if recursion_depth > 0 and len(job_spec.seed_urls) > 1:
        subscan_root = out_dir / "subscans"
        subscan_root.mkdir(parents=True, exist_ok=True)
        single_seed_total = estimate_single_seed_requests(args.wordlist, extensions)
        used_subscan_names: set[str] = set()
        for index, seed_url in enumerate(job_spec.seed_urls, start=1):
            base_name = f"{index:03d}_{seed_slug(seed_url)}"
            subscan_name = base_name
            if subscan_name in used_subscan_names:
                subscan_name = f"{base_name}_{sha256_text(seed_url)[:8]}"
            used_subscan_names.add(subscan_name)
            subscan_out_dir = subscan_root / subscan_name
            subscan_out_dir.mkdir(parents=True, exist_ok=True)
            subscan_cmd = build_ffuf_cmd(
                seeds_file=seeds_file,
                wordlist=args.wordlist,
                out_dir=subscan_out_dir,
                rate=args.rate,
                headers=headers,
                proxy=args.proxy,
                extensions=extensions,
                follow_redirects=args.follow_redirects,
                recursion_depth=recursion_depth,
                recursion_strategy=recursion_strategy,
                base_url=seed_url,
            )
            subscans.append(
                FfufSubscan(
                    index=index,
                    total=len(job_spec.seed_urls),
                    seed_url=seed_url,
                    out_dir=subscan_out_dir,
                    cmd=subscan_cmd,
                    command_text=shlex.join(subscan_cmd),
                    estimated_total=single_seed_total,
                )
            )
        commands = [subscan.cmd for subscan in subscans]
        cmd = commands[0]
        total = single_seed_total * len(subscans)
        subscan_totals = [subscan.estimated_total for subscan in subscans]
    else:
        base_url = job_spec.seed_urls[0] if recursion_depth > 0 and len(job_spec.seed_urls) == 1 else None
        cmd = build_ffuf_cmd(
            seeds_file=seeds_file,
            wordlist=args.wordlist,
            out_dir=out_dir,
            rate=args.rate,
            headers=headers,
            proxy=args.proxy,
            extensions=extensions,
            follow_redirects=args.follow_redirects,
            recursion_depth=recursion_depth,
            recursion_strategy=recursion_strategy,
            base_url=base_url,
        )
        commands = [cmd]
        total = estimate_single_seed_requests(args.wordlist, extensions) if base_url else estimate_total_requests(seeds_file, args.wordlist, extensions)
        subscan_totals = []

    command_text = "\n".join(shell_lines(commands))
    (out_dir / "command.txt").write_text(command_text + "\n", encoding="utf-8")
    hashes = build_job_hashes(seeds_file=seeds_file, wordlist=args.wordlist, command_text=command_text)

    return FfufJob(
        job_id=job_id,
        name=job_spec.name,
        seeds_file=seeds_file,
        out_dir=out_dir,
        total=total,
        rate=args.rate,
        cmd=cmd,
        command_text=command_text,
        hashes=hashes,
        stderr_log=out_dir / "ffuf.stderr.log",
        stop_aliases=build_stop_aliases(job_spec.name, job_spec.seed_urls),
        subscans=subscans,
        subscan_total_count=max(1, len(subscans)),
        subscan_totals=subscan_totals,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = create_argument_parser(
        description="Run multiple ffuf jobs in parallel from a URL file or a Katana paths directory.",
        epilog=(
            "Examples:\n"
            "  FFuFScan.py -i targets.txt -w /path/to/fuzz.txt\n"
            "  FFuFScan.py --paths-dir katana/paths -w /path/to/fuzz.txt -p 4 --keep-going\n"
            "  FFuFScan.py -i targets.txt -w /path/to/fuzz.txt --header 'Authorization: Bearer XXX' --proxy http://127.0.0.1:8080\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "-i",
        "--input",
        type=Path,
        help="File with HTTP(S) seed URLs. Jobs are grouped by origin.",
    )
    source_group.add_argument(
        "--paths-dir",
        type=Path,
        help="Directory with *_Katana.txt files from KatanaScan.py paths mode.",
    )

    parser.add_argument(
        "-w",
        "--wordlist",
        type=Path,
        required=True,
        help="Wordlist file for FUZZ.",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("./ffuf"),
        help="Root directory for ffuf job outputs. Default: ./ffuf",
    )
    parser.add_argument(
        "-p",
        "--parallel",
        type=int,
        default=2,
        help="Maximum number of concurrent ffuf jobs. Default: 2",
    )
    parser.add_argument(
        "-r",
        "--rate",
        type=int,
        default=300,
        help="ffuf -rate value for each job. Default: 300",
    )
    parser.add_argument(
        "-e",
        "--extensions",
        type=str,
        default=None,
        help="Comma-separated extension list for ffuf -e, for example: php,asp,aspx",
    )
    parser.add_argument(
        "-H",
        "--header",
        "--headers",
        dest="headers",
        action="append",
        help='Additional ffuf header, repeat as needed. Example: -H "Cookie: name=value"',
    )
    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="Proxy to pass to ffuf -x, for example: http://127.0.0.1:8080",
    )
    parser.add_argument(
        "-fr",
        "--follow-redirects",
        action="store_true",
        help="Pass -r to ffuf to follow redirects.",
    )
    parser.add_argument(
        "-rd",
        "--recursion-depth",
        type=int,
        default=0,
        help="Enable ffuf recursion with the provided maximum depth. Default: 0 (disabled).",
    )
    parser.add_argument(
        "-rs",
        "--recursion-strategy",
        choices=("default", "greedy"),
        default="default",
        help="ffuf recursion strategy when recursion is enabled. Default: default.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Skip jobs whose result.json already exists and is non-empty.",
    )
    parser.add_argument(
        "--show-cmds",
        action="store_true",
        help="Print the exact ffuf command for each job before starting.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue processing other jobs even if one ffuf job fails.",
    )
    return parser.parse_args(argv)


def render_status(
    running: list[FfufJob],
    waiting_count: int,
    finished_count: int,
    failed_count: int,
    stopped_count: int,
    skipped_count: int,
    total_jobs: int,
    parallel: int,
    rate: int,
    control_messages: list[str] | None = None,
    interactive_enabled: bool = False,
    console_prompt: str | None = None,
) -> int:
    """Render the current ffuf job table and return line count."""
    header = (
        f"FFUF total={total_jobs} done={finished_count} failed={failed_count} "
        f"stopped={stopped_count} skipped={skipped_count} running={len(running)} waiting={waiting_count} "
        f"parallel={parallel} rate={rate}"
    )
    if interactive_enabled:
        header += " | controls: s <id|host>, jobs, stops, help"

    lines = [header]
    if not running and waiting_count == 0:
        lines.append("  all jobs finished")
    elif not running:
        lines.append("  waiting to start")
    else:
        for job in running:
            now = time.time()
            state, extra = running_job_display_state(job, now)
            lines.append(
                format_job_line(
                    job.job_id,
                    job.name,
                    job.done_est,
                    job.total,
                    job.progress_rate,
                    state,
                    int(max(0.0, now - job.started)),
                    extra=extra,
                )
            )

    if control_messages:
        lines.extend(f"  {message}" for message in control_messages[-5:])
    if console_prompt is not None:
        lines.append(console_prompt)

    sys.stdout.write("\n".join(lines))
    sys.stdout.flush()
    return len(lines)


def main(argv: list[str] | None = None) -> int:
    """Run parallel ffuf jobs from a URL file or Katana paths directory."""
    args = parse_args(argv)

    if shutil.which("ffuf") is None:
        print("Error: 'ffuf' was not found in PATH.", file=sys.stderr)
        return 1

    if args.parallel < 1:
        print("Error: --parallel must be at least 1.", file=sys.stderr)
        return 1

    if args.rate < 1:
        print("Error: --rate must be at least 1.", file=sys.stderr)
        return 1

    if args.recursion_depth < 0:
        print("Error: --recursion-depth must be 0 or greater.", file=sys.stderr)
        return 1

    if args.recursion_depth > 0 and args.recursion_strategy == "default" and args.follow_redirects:
        print(
            "Error: -fr/--follow-redirects cannot be used with --recursion-strategy default because "
            "ffuf default recursion relies on redirects. Remove -fr or use -rs greedy.",
            file=sys.stderr,
        )
        return 1

    args.output_dir = Path(str(args.output_dir)).expanduser()
    args.wordlist = Path(str(args.wordlist)).expanduser()
    if args.input is not None:
        args.input = Path(str(args.input)).expanduser()
    if args.paths_dir is not None:
        args.paths_dir = Path(str(args.paths_dir)).expanduser()

    if not args.wordlist.is_file():
        print(f"Error: Wordlist file '{args.wordlist}' not found.", file=sys.stderr)
        return 1

    if count_nonempty_lines(args.wordlist) == 0:
        print(f"Error: Wordlist file '{args.wordlist}' is empty.", file=sys.stderr)
        return 1

    if args.input is not None:
        if not args.input.is_file():
            print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
            return 1
        specs = build_specs_from_url_file(args.input)
    else:
        if not args.paths_dir.is_dir():
            print(f"Error: Paths directory '{args.paths_dir}' not found.", file=sys.stderr)
            return 1
        specs = build_specs_from_paths_dir(args.paths_dir)

    if not specs:
        print("Error: No usable ffuf jobs were built from the provided input.", file=sys.stderr)
        return 1

    extensions = [item.strip() for item in args.extensions.split(",") if item.strip()] if args.extensions else None

    args.output_dir.mkdir(parents=True, exist_ok=True)

    jobs: list[FfufJob] = []
    skipped_count = 0
    summaries: list[dict[str, object]] = []
    for job_id, spec in enumerate(specs, start=1):
        job = prepare_job(spec, args, extensions, job_id=job_id)
        if args.resume:
            resumed_state = load_resume_state(job.out_dir, job.hashes)
            if resumed_state is not None:
                summaries.append(resumed_state)
                skipped_count += 1
                continue
        jobs.append(job)

    if args.show_cmds:
        for job in jobs:
            for command in job_commands(job):
                print("$ " + shlex.join(command))

    if not jobs:
        write_index_files(args.output_dir, summaries)
        write_unique_paths_html(args.output_dir, summaries)
        print("All jobs were skipped by --resume.", file=sys.stderr)
        return 0

    waiting = jobs.copy()
    running: list[FfufJob] = []
    finished: list[FfufJob] = []
    failed_jobs: list[FfufJob] = []
    aborted_jobs: list[FfufJob] = []
    stopped_jobs: list[FfufJob] = []
    stop_requests: list[StopRequest] = []
    control_messages: list[str] = []
    console = InteractiveConsole()
    console.start()
    interactive_enabled = console.enabled
    last_rendered = 0
    abort_requested = False

    try:
        try:
            while waiting or running:
                for command in console.read_commands():
                    request, messages = handle_interactive_command(
                        command,
                        stop_requests=stop_requests,
                        running=running,
                        waiting=waiting,
                    )
                    if request:
                        if request in stop_requests:
                            messages = [f"Stop already requested: {format_stop_request(request)}"]
                        else:
                            stop_requests.append(request)
                    control_messages.extend(messages)

                control_messages.extend(
                    apply_stop_requests(
                        running=running,
                        waiting=waiting,
                        finished=finished,
                        stopped_jobs=stopped_jobs,
                        stop_requests=stop_requests,
                    )
                )

                while waiting and len(running) < args.parallel:
                    job = waiting.pop(0)
                    matched = next((request for request in stop_requests if job_matches_stop_request(job, request)), None)
                    if matched is not None:
                        matched_label = format_stop_request(matched)
                        stop_job(job, reason=f"manual stop before start matched: {matched_label}")
                        finished.append(job)
                        stopped_jobs.append(job)
                        control_messages.append(f"Stopped waiting job #{job.job_id} {job.name} ({matched_label})")
                        continue
                    run_ffuf_background(job)
                    running.append(job)

                for job in list(running):
                    update_job_progress_from_stderr(job)
                    reap_job(job)
                    if not job.finished:
                        continue
                    running.remove(job)
                    finished.append(job)
                    if job.failed:
                        failed_jobs.append(job)
                        if not args.keep_going:
                            abort_requested = True
                            for other in list(running):
                                if other.proc and other.proc.poll() is None:
                                    try:
                                        other.proc.terminate()
                                    except OSError:
                                        pass
                                    try:
                                        other.proc.wait(timeout=2)
                                    except subprocess.TimeoutExpired:
                                        try:
                                            other.proc.kill()
                                        except OSError:
                                            pass
                                    other.retcode = other.proc.returncode
                                other.finished = True
                                other.failed = True
                                other.duration_seconds = max(0.0, time.time() - other.started)
                                aggregate_recursive_subscan_outputs(other)
                                other.result_count = read_result_count(other.out_dir / "result.json")
                                running.remove(other)
                                finished.append(other)
                                aborted_jobs.append(other)
                            waiting.clear()
                            break
                    else:
                        cleanup_ffuf_outputs(job.out_dir)

                if abort_requested:
                    break

                clear_lines(last_rendered)
                last_rendered = render_status(
                    running=running,
                    waiting_count=len(waiting),
                    finished_count=len(finished),
                    failed_count=len(failed_jobs),
                    stopped_count=len(stopped_jobs),
                    skipped_count=skipped_count,
                    total_jobs=len(jobs) + skipped_count,
                    parallel=args.parallel,
                    rate=args.rate,
                    control_messages=control_messages,
                    interactive_enabled=interactive_enabled,
                    console_prompt=console.prompt_line() if interactive_enabled else None,
                )
                time.sleep(0.2)
        except KeyboardInterrupt:
            for job in running:
                if job.proc and job.proc.poll() is None:
                    try:
                        job.proc.terminate()
                    except OSError:
                        pass
            print("Interrupted.", file=sys.stderr)
            return 130
    finally:
        console.stop()
        if last_rendered:
            sys.stdout.write("\n")
            sys.stdout.flush()

    for job in finished:
        if job.stopped:
            summaries.append(write_job_state(job, output_root=args.output_dir, status="stopped"))
        elif job.failed and job in aborted_jobs:
            summaries.append(write_job_state(job, output_root=args.output_dir, status="aborted"))
        else:
            summaries.append(write_job_state(job, output_root=args.output_dir))

    write_index_files(args.output_dir, summaries)
    write_unique_paths_html(args.output_dir, summaries)

    if failed_jobs:
        print("\nFailed jobs:", file=sys.stderr)
        for job in failed_jobs:
            print(f"  {job.name}: {job.stderr_log}", file=sys.stderr)
            for line in tail_lines(job.stderr_log, limit=10):
                print(f"    {line}", file=sys.stderr)
        for job in aborted_jobs:
            print(f"  {job.name}: terminated after fail-fast stop", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
