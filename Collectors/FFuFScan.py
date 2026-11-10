#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
from html import escape as html_escape
import io
import ipaddress
import json
import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
try:
    import termios
    import tty
except ImportError:  # pragma: no cover - non-POSIX fallback
    termios = None
    tty = None
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


KATANA_SUFFIX = "_Katana.txt"
PROGRESS_RE = re.compile(r"Progress:\s*\[(\d+)/(\d+)\]")
FFUF_JOB_RE = re.compile(r"Job\s*\[(\d+)/(\d+)\]")
SUBSCAN_RE = re.compile(r"FFUFScan subscan:\s*\[(\d+)/(\d+)\]\s+total=(\d+)")
ERRORS_RE = re.compile(r"Errors:\s*(\d+)")
RATE_RE = re.compile(r"(\d+) req/sec")
ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
QUEUED_TARGET_RE = re.compile(r"Starting queued job on target:\s*(\S+)")
LIVE_MATCH_LIMIT = 100
PRIMARY_RESULT_EXTENSIONS = (".json", ".html", ".md", ".csv")
EXTRA_RESULT_EXTENSIONS = (".ejson", ".ecsv")


def create_argument_parser(*args, **kwargs) -> argparse.ArgumentParser:
    try:
        return argparse.ArgumentParser(*args, color=False, **kwargs)
    except TypeError:
        return argparse.ArgumentParser(*args, **kwargs)


def parse_user_agent(raw: str) -> str:
    """Validate an explicit User-Agent value without accepting control characters."""
    if not raw.strip() or any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise argparse.ArgumentTypeError("User-Agent must be non-empty and contain no control characters")
    return raw.strip()


def headers_with_user_agent(headers: list[str] | None, user_agent: str | None) -> list[str] | None:
    """Add one canonical UA header, rejecting conflicting explicit values."""
    if user_agent is None:
        return headers
    merged: list[str] = []
    for header in headers or []:
        name, separator, value = header.partition(":")
        if name.strip().lower() == "user-agent":
            if not separator or value.strip() != user_agent:
                raise ValueError("--user-agent conflicts with a User-Agent supplied through --header")
        else:
            merged.append(header)
    return merged + [f"User-Agent: {user_agent}"]


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
    if not isinstance(data, dict):
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
    normalized = ANSI_RE.sub("", text).replace("\r", "\n").replace(":: Progress:", "\n:: Progress:")
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


def build_job_hashes(
    seeds_file: Path, wordlist: Path, command_text: str, *, seeds_text: str | None = None,
) -> dict[str, str]:
    """Build the resume-relevant hashes for a job."""
    return {
        "paths_sha256": sha256_file(seeds_file) if seeds_text is None else sha256_text(seeds_text),
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

    if not isinstance(state, dict) or state.get("status") != "done":
        return None
    if state.get("hashes") != hashes:
        return None
    if checked_reports(out_dir) is None:
        return None
    if state.get("checkpoint_version") == 1:
        records = state.get("passes")
        if not isinstance(records, list) or not records or not all(
            isinstance(record, dict) and record.get("status") == "done" and checkpoint_reports_valid(out_dir, record)
            for record in records
        ):
            return None
        if state.get("report_hashes") != checked_reports(out_dir):
            return None

    resumed_state = dict(state)
    resumed_state["status"] = "skipped"
    resumed_state["resumed"] = True
    result_count = read_result_count(out_dir / "result.json")
    if result_count is not None:
        resumed_state["result_count"] = result_count
    if state.get("checkpoint_version") != 1:
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
    return build_specs_from_urls(read_seed_urls(path))


def build_specs_from_urls(urls: list[str]) -> list[JobSpec]:
    """Group origins independently of source filenames and deduplicate their seeds."""
    grouped: dict[str, list[str]] = {}
    for url in urls:
        grouped.setdefault(origin_from_url(url), []).append(url)

    return [
        JobSpec(name=job_name_from_origin(origin), seed_urls=dedupe_preserve_order(seed_urls))
        for origin, seed_urls in grouped.items()
    ]


def read_paths_file(path: Path) -> list[str]:
    """Read Katana directory URLs with a trailing slash for URLFUZZ joining."""
    urls: list[str] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            normalized = normalize_url(stripped)
            urls.append(normalized.rstrip("/") + "/")
        except ValueError as exc:
            print(
                f"Warning: skipping invalid URL in {path.name}:{line_number}: {stripped} ({exc})",
                file=sys.stderr,
            )
    return dedupe_preserve_order(urls)


def build_specs_from_paths_dir(directory: Path) -> list[JobSpec]:
    """Merge Katana seed files into one job per origin."""
    urls: list[str] = []
    for path_file in sorted(directory.glob(f"*{KATANA_SUFFIX}")):
        urls.extend(read_paths_file(path_file))
    return build_specs_from_urls(urls)


def host_key_from_url(url: str) -> str:
    """Group literal IPs across ports/schemes; keep DNS names without resolving."""
    hostname = (urlsplit(url).hostname or "").lower().rstrip(".")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return hostname
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return address.compressed


def rate_per_host(total_rate: int, parallel: int) -> int:
    """Allocate a fixed ceil(total / configured slots), including idle slots."""
    if total_rate < 1 or parallel < 1:
        raise ValueError("rate and parallel slots must be positive")
    return (total_rate + parallel - 1) // parallel


def job_host_key(job: FfufJob) -> str:
    return job.host_key or job.name


def next_available_job_index(waiting: list[FfufJob], running: list[FfufJob]) -> int | None:
    """Skip busy hosts so another port cannot occupy a second slot for one IP."""
    busy = {job_host_key(job) for job in running}
    return next((index for index, job in enumerate(waiting) if job_host_key(job) not in busy), None)


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
        "-json",
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
class FfufPass:
    index: int
    seed_url: str
    out_dir: Path
    cmd: list[str]
    total: int
    status: str = "queued"
    started: float = 0.0
    duration: float = 0.0
    result_count: int = 0
    done: int = 0
    errors: int | None = None
    exit_code: int | None = None
    task_done: int | None = None
    task_total: int | None = None
    task_current: int | None = None
    task_count: int | None = None
    task_template: str = ""
    task_duration: float = 0.0
    stderr_start: int = 0
    matches_start: int = 0
    reports: dict[str, str] = field(default_factory=dict)
    recent_matches: list[dict[str, object]] = field(default_factory=list)


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
    host_key: str = ""
    origin: str = ""
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
    subscan_pending: bool = False
    seed_urls: list[str] = field(default_factory=list)
    pass_started: float = 0.0
    task_started: float = 0.0
    task_template: str = ""
    task_done: int | None = None
    task_total: int | None = None
    seed_done: int = 0
    seed_total: int = 0
    matches_offset: int = 0
    matches_remainder: bytes = b""
    live_hits: int = 0
    recent_matches: list[dict[str, object]] = field(default_factory=list)
    passes: list[FfufPass] = field(default_factory=list)
    checkpoint_enabled: bool = False
    partial_resumed: bool = False
    previous_duration: float = 0.0
    failure_reason: str | None = None
    pass_interrupted: bool = False


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
        aliases.add(host_key_from_url(seed_url))
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
        return None, ["Commands: s <id|host|job>, stop <id|host|job>, jobs, stops, help; p pause new passes; l toggle log; arrows move; Tab hosts/origins; Enter expand; Esc back; PgUp/PgDn scroll details"]
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
        self._escape_sequence = ""
        self._escape_started = 0.0
        self._last_cr = False

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
            if char == "\n" and self._last_cr:
                self._last_cr = False
                continue
            self._last_cr = char == "\r"
            if self._escape_sequence:
                if self._escape_sequence == "\x1b" and char != "[":
                    commands.append("__escape__")
                    self._escape_sequence = ""
                else:
                    self._escape_sequence += char
                    keys = {"\x1b[A": "__up__", "\x1b[B": "__down__",
                            "\x1b[5~": "__page_up__", "\x1b[6~": "__page_down__"}
                    if self._escape_sequence in keys:
                        commands.append(keys[self._escape_sequence])
                    if char.isalpha() or char == "~":
                        self._escape_sequence = ""
                    continue
            if char == "\x1b":
                self._escape_sequence = "\x1b"
                self._escape_started = time.monotonic()
                continue
            if char == "\x03":
                raise KeyboardInterrupt
            if char in {"\r", "\n"}:
                command = self.buffer.strip()
                self.buffer = ""
                commands.append(command if command else "__enter__")
                continue
            if char == "\t":
                commands.append("__tab__")
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
            # Allow split arrow-key sequences, but also recognize a standalone Esc.
            if self._escape_sequence and time.monotonic() - self._escape_started >= 0.1:
                if self._escape_sequence == "\x1b":
                    commands.append("__escape__")
                    self.buffer = ""
                self._escape_sequence = ""
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
    job.subscan_pending = False
    job.failed = False
    job.finished = True
    job.stop_reason = reason
    job.stop_requested_at = now
    if job.started > 0:
        job.duration_seconds = job.previous_duration + max(0.0, now - job.started)

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
    if job.started:
        update_job_progress_from_stderr(job)
        update_job_matches(job, drain=True)
    job.checkpoint_enabled = bool(job.passes)
    finish_pass(job, "stopped")
    for item in job.passes:
        if item.status == "queued":
            item.status = "stopped"
    aggregate_recursive_subscan_outputs(job)
    job.result_count = read_result_count(job.out_dir / "result.json") if job.started or any(item.status == "done" for item in job.passes) else 0
    if job.checkpoint_enabled:
        write_job_state(job, job.out_dir.parent, status="stopped")


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
    job.ffuf_errors = None
    job.pass_interrupted = False
    now = time.time()
    job.pass_started = now
    job.task_started = now
    job.task_template = command_option(cmd, "-u") or "URLFUZZ"
    job.task_done = None
    job.task_total = None
    job.seed_done = 0
    job.seed_total = current_subscan.estimated_total if current_subscan else job.total
    job.progress_rate = 0.0
    job.last_progress_time = 0.0
    job.last_display_progress_value = job.done_est
    job.last_stderr_activity = now
    if truncate_log:
        job.progress_offset = 0
        job.progress_remainder = ""
        job.matches_offset = 0
        job.matches_remainder = b""
        if not job.partial_resumed:
            job.live_hits = 0
            job.recent_matches.clear()
    item = active_pass(job)
    if job.checkpoint_enabled and item:
        item.status = "running"
        item.started = now
        item.result_count = 0
        item.recent_matches.clear()
        item.stderr_start = 0 if truncate_log or not job.stderr_log.exists() else job.stderr_log.stat().st_size
        matches_log = job.out_dir / "ffuf.matches.jsonl"
        item.matches_start = 0 if truncate_log or not matches_log.exists() else matches_log.stat().st_size
        # A failed/interrupted attempt's files must not become a successful pass.
        for extension in PRIMARY_RESULT_EXTENSIONS + EXTRA_RESULT_EXTENSIONS:
            (item.out_dir / f"result{extension}").unlink(missing_ok=True)
        write_job_state(job, job.out_dir.parent, status="running")
    stderr_handle = job.stderr_log.open("w" if truncate_log else "a", encoding="utf-8")
    if current_subscan is not None:
        write_subscan_marker(stderr_handle, current_subscan)
    try:
        # A regular file cannot fill a pipe and block ffuf while the UI renders.
        with (job.out_dir / "ffuf.matches.jsonl").open("wb" if truncate_log else "ab") as matches_handle:
            job.proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=matches_handle,
                stderr=stderr_handle, text=True,
            )
    finally:
        stderr_handle.close()


def run_ffuf_background(job: FfufJob) -> None:
    """Start ffuf for one job in the background."""
    job.started = time.time()
    job.checkpoint_enabled = bool(job.passes)
    index = next_pending_pass(job) if job.passes else 0
    if index is None:
        aggregate_recursive_subscan_outputs(job)
        job.finished = True
        job.retcode = 0
        job.duration_seconds = job.previous_duration
        job.result_count = read_result_count(job.out_dir / "result.json")
        write_job_state(job, job.out_dir.parent)
        return
    job.active_subscan_index = index
    start_active_ffuf_process(job, truncate_log=True)


def command_option(command: list[str], flag: str) -> str | None:
    """Read a value from an already-built command without executing it."""
    try:
        return command[command.index(flag) + 1]
    except (ValueError, IndexError):
        return None



def atomic_write_text(path: Path, text: str) -> None:
    """Replace a state file only after its complete contents reach disk."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def checked_reports(directory: Path) -> dict[str, str] | None:
    """An empty results list is valid; missing or malformed reports are not."""
    try:
        paths = [directory / f"result{extension}" for extension in PRIMARY_RESULT_EXTENSIONS]
        if not all(path.is_file() for path in paths):
            return None
        data = json.loads(paths[0].read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("results"), list):
            return None
        if not all(isinstance(item, dict) for item in data["results"]):
            return None
        return {path.suffix: sha256_file(path) for path in paths}
    except (OSError, ValueError):
        return None


def pass_record(item: FfufPass, root: Path) -> dict[str, object]:
    return {
        "index": item.index, "seed_url": item.seed_url,
        "directory": relpath_or_absolute(root, item.out_dir),
        "command_sha256": sha256_text(shlex.join(item.cmd)),
        "status": item.status, "started": item.started, "duration": item.duration,
        "result_count": item.result_count, "done": item.done, "total": item.total,
        "errors": item.errors, "exit_code": item.exit_code,
        "task_done": item.task_done, "task_total": item.task_total,
        "task_current": item.task_current, "task_count": item.task_count,
        "task_template": item.task_template, "reports": item.reports,
        "task_duration": item.task_duration,
    }


def compact_match(item: dict[str, object]) -> dict[str, object]:
    return {key: item.get(key) for key in ("url", "status", "length", "words", "redirectlocation")}


def checkpoint_reports_valid(root: Path, record: dict[str, object]) -> bool:
    directory = record.get("directory")
    if not isinstance(directory, str):
        return False
    path = Path(directory)
    if path.is_absolute() or ".." in path.parts:
        return False
    expected = record.get("reports")
    return isinstance(expected, dict) and bool(expected) and checked_reports(root / path) == expected


def load_partial_resume(job: FfufJob) -> int:
    """Restore independently verified passes, leaving all other passes queued."""
    try:
        state = json.loads((job.out_dir / "job.json").read_text(encoding="utf-8"))
        if not isinstance(state, dict) or state.get("checkpoint_version") != 1 or state.get("hashes") != job.hashes:
            return 0
        records = state.get("passes")
        if not isinstance(records, list) or len(records) != len(job.passes):
            return 0
        restored = 0
        for item, record in zip(job.passes, records):
            if not isinstance(record, dict) or record.get("index") != item.index or record.get("seed_url") != item.seed_url:
                continue
            if record.get("command_sha256") != sha256_text(shlex.join(item.cmd)):
                continue
            if record.get("status") != "done" or not checkpoint_reports_valid(job.out_dir, record):
                continue
            # Optional display fields must never prevent a safe restart.
            item.status = "done"
            item.reports = dict(record["reports"])
            for attr in ("started", "duration", "done", "total", "errors", "task_done", "task_total", "task_current", "task_count", "task_duration"):
                value = record.get(attr)
                expected_type = (int, float) if attr in {"started", "duration", "task_duration"} else (int,)
                if type(value) in expected_type and 0 <= value < 10**15:
                    setattr(item, attr, value)
            item.exit_code = 0
            item.task_template = str(record.get("task_template") or command_option(item.cmd, "-u") or "URLFUZZ")
            results = read_ffuf_result_items(item.out_dir / "result.json")
            item.result_count = len(results)
            item.recent_matches = [compact_match(row) for row in results[-LIVE_MATCH_LIMIT:]]
            if job.subscan_totals:
                job.subscan_totals[item.index - 1] = max(item.total, item.done)
            restored += 1
        if restored:
            job.checkpoint_enabled = True
            job.partial_resumed = True
            job.previous_duration = sum(item.duration for item in job.passes if item.status == "done")
            job.done_est = sum(item.total for item in job.passes if item.status == "done")
            job.total = sum(item.total for item in job.passes)
            job.live_hits = sum(item.result_count for item in job.passes if item.status == "done")
            job.recent_matches = [row for item in job.passes if item.status == "done" for row in item.recent_matches][-LIVE_MATCH_LIMIT:]
        return restored
    except (OSError, ValueError, TypeError):
        return 0


def active_pass(job: FfufJob) -> FfufPass | None:
    return job.passes[job.active_subscan_index] if job.passes else None


def next_pending_pass(job: FfufJob) -> int | None:
    return next((index for index, item in enumerate(job.passes) if item.status != "done"), None)


def copy_log_segment(source: Path, target: Path, start: int) -> None:
    if source == target or not source.exists():
        return
    with source.open("rb") as reader, target.open("wb") as writer:
        reader.seek(start)
        shutil.copyfileobj(reader, writer, length=64 * 1024)


def finish_pass(job: FfufJob, status: str) -> None:
    """Capture a process's history before another seed can overwrite counters."""
    item = active_pass(job)
    if item is None or not job.checkpoint_enabled or item.status != "running":
        return
    item.status = status
    item.duration = max(0.0, time.time() - item.started)
    item.done, item.total = job.seed_done, job.seed_total
    item.errors, item.exit_code = job.ffuf_errors, job.proc.returncode if job.proc else None
    item.task_done, item.task_total = job.task_done, job.task_total
    item.task_current, item.task_count = job.ffuf_job_current, job.ffuf_job_total
    item.task_template = job.task_template
    item.task_duration = max(0.0, time.time() - job.task_started) if job.task_started else 0.0
    item.recent_matches = list(item.recent_matches)
    if status == "done":
        item.reports = checked_reports(item.out_dir) or {}
        if not item.reports:
            item.status = "failed"
            job.failure_reason = f"Seed pass {item.index}: ffuf exited without valid result.json/html/md/csv"
        else:
            item.result_count = read_result_count(item.out_dir / "result.json") or 0
            if not item.recent_matches:
                item.recent_matches = [compact_match(row) for row in read_ffuf_result_items(item.out_dir / "result.json")[-LIVE_MATCH_LIMIT:]]
            item.total = max(item.total, item.done)
            item.done = item.total
    copy_log_segment(job.stderr_log, item.out_dir / "ffuf.stderr.log", item.stderr_start)
    copy_log_segment(job.out_dir / "ffuf.matches.jsonl", item.out_dir / "ffuf.matches.jsonl", item.matches_start)
    job.duration_seconds = job.previous_duration + max(0.0, time.time() - job.started)
    # The checkpoint contains the pass before aggregation or another subprocess starts.
    write_job_state(job, job.out_dir.parent, status="running")


def inspection_job(job: FfufJob, index: int | None) -> FfufJob:
    """A detached display snapshot prevents inspecting history from changing work."""
    if index is None or index < 0 or index >= len(job.passes):
        return job
    item = job.passes[index]
    current = item.status == "running"
    return replace(
        job, active_subscan_index=index, cmd=item.cmd, started=item.started,
        pass_started=item.started, task_started=job.task_started if current else item.started + item.duration - item.task_duration if item.task_duration else 0.0,
        finished=item.status not in {"queued", "running"}, failed=item.status == "failed",
        stopped=item.status in {"stopped", "interrupted"}, duration_seconds=item.duration,
        seed_done=job.seed_done if current else item.done, seed_total=job.seed_total if current else item.total,
        task_done=job.task_done if current else item.task_done, task_total=job.task_total if current else item.task_total,
        task_template=job.task_template if current else item.task_template,
        ffuf_job_current=job.ffuf_job_current if current else item.task_current,
        ffuf_job_total=job.ffuf_job_total if current else item.task_count,
        ffuf_errors=job.ffuf_errors if current else item.errors,
        result_count=item.result_count, live_hits=item.result_count, recent_matches=item.recent_matches,
        stderr_log=job.stderr_log if current else item.out_dir / "ffuf.stderr.log",
        previous_duration=0.0,
        last_progress_time=job.last_progress_time if current else item.started + item.duration if item.done else 0.0,
    )

def update_job_matches(job: FfufJob, *, drain: bool = False) -> None:
    """Tail JSONL matches with bounded UI memory and bounded work per refresh."""
    try:
        with (job.out_dir / "ffuf.matches.jsonl").open("rb") as handle:
            handle.seek(job.matches_offset)
            while True:
                chunk = handle.read(256 * 1024)
                if not chunk:
                    break
                job.matches_offset += len(chunk)
                lines = (job.matches_remainder + chunk).split(b"\n")
                job.matches_remainder = lines.pop()
                for line in lines:
                    try:
                        item = json.loads(line)
                    except (ValueError, UnicodeError):
                        continue
                    if not isinstance(item, dict) or not isinstance(item.get("url"), str):
                        continue
                    job.live_hits += 1
                    job.recent_matches.append(compact_match(item))
                    del job.recent_matches[:-LIVE_MATCH_LIMIT]
                    item_pass = active_pass(job)
                    if job.checkpoint_enabled and item_pass and item_pass.status == "running":
                        item_pass.result_count += 1
                        item_pass.recent_matches.append(job.recent_matches[-1])
                        del item_pass.recent_matches[:-LIVE_MATCH_LIMIT]
                # Malformed/non-JSON output must not grow the pending buffer forever.
                if len(job.matches_remainder) > 1024 * 1024:
                    job.matches_remainder = b""
                if not drain:
                    break
    except OSError:
        return


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
    combined = (job.progress_remainder + text).replace(":: Progress:", "\n:: Progress:")
    lines = combined.split("\n")

    if combined and not combined.endswith("\n"):
        job.progress_remainder = lines.pop()
        # ffuf writes progress with carriage returns and no final newline.
        tail = ANSI_RE.sub("", job.progress_remainder).strip()
        if PROGRESS_RE.search(tail) and ERRORS_RE.search(tail) and tail.endswith("::"):
            lines.append(job.progress_remainder)
            job.progress_remainder = ""
    else:
        job.progress_remainder = ""

    for line in lines:
        line = ANSI_RE.sub("", line)
        if "Caught keyboard interrupt" in line:
            job.pass_interrupted = True
        target_match = QUEUED_TARGET_RE.search(line)
        if target_match:
            job.task_template = target_match.group(1)
            job.task_started = time.time()
            job.task_done = None
            job.task_total = None
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
            if job.ffuf_job_current is not None and job.ffuf_job_current != int(job_match.group(1)):
                job.task_started = time.time()
                job.last_progress_time = 0.0
            job.ffuf_job_current = int(job_match.group(1))
            job.ffuf_job_total = int(job_match.group(2))

        match = PROGRESS_RE.search(line)
        if match:
            now = time.time()
            current = int(match.group(1))
            total = int(match.group(2))
            job.task_done = current
            job.task_total = total
            job.ffuf_progress_done = current
            job.ffuf_progress_total = total
            if total > 0:
                display_current, display_total = ffuf_display_progress(
                    current,
                    total,
                    job.ffuf_job_current,
                    job.ffuf_job_total,
                )
                job.seed_done, job.seed_total = display_current, display_total
                if job.subscan_totals:
                    display_current, display_total = subscan_aggregate_progress(
                        job.subscan_totals,
                        job.active_subscan_index,
                        display_current,
                        display_total,
                    )
                if job.checkpoint_enabled:
                    display_current = sum(item.total for item in job.passes if item.status == "done") + job.seed_done
                    display_total = sum(item.total if item.status == "done" else max(item.total, job.seed_total) if item is active_pass(job) else item.total for item in job.passes)
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
            rate_match = RATE_RE.search(line)
            if rate_match:
                job.progress_rate = float(rate_match.group(1))

        errors_match = ERRORS_RE.search(line)
        if errors_match:
            job.ffuf_errors = int(errors_match.group(1))

    return True


def reap_job(job: FfufJob, *, start_next: bool = True) -> None:
    """Update job completion state from the child process."""
    if job.subscan_pending and not job.finished:
        if start_next:
            job.subscan_pending = False
            start_active_ffuf_process(job, truncate_log=False)
        return
    if job.finished or not job.proc:
        return
    retcode = job.proc.poll()
    if retcode is None:
        return
    # Capture the final records/counters before switching to another seed.
    update_job_progress_from_stderr(job)
    update_job_matches(job, drain=True)
    incomplete = job.pass_interrupted or (
        job.task_total is not None and (job.task_done or 0) < job.task_total
    ) or (job.ffuf_job_current is not None and job.ffuf_job_total is not None and job.ffuf_job_current < job.ffuf_job_total)
    if retcode == 0 and incomplete and job.checkpoint_enabled:
        job.failure_reason = "ffuf stopped before completing this seed pass; its partial report is not a completed checkpoint"
        finish_pass(job, "interrupted")
        retcode = 1
    else:
        finish_pass(job, "done" if retcode == 0 else "failed")
    if job.checkpoint_enabled and active_pass(job) and active_pass(job).status == "failed":
        retcode = retcode or 1
    next_index = next_pending_pass(job) if job.checkpoint_enabled else job.active_subscan_index + 1
    has_next = next_index is not None and (job.checkpoint_enabled or next_index < len(job.subscans))
    if retcode == 0 and job.subscans and has_next:
        if job.checkpoint_enabled:
            job.done_est = sum(item.total for item in job.passes if item.status == "done")
        elif job.subscan_totals:
            completed_index = max(0, min(job.active_subscan_index, len(job.subscan_totals) - 1))
            job.done_est = min(sum(job.subscan_totals[: completed_index + 1]), max(job.total, 1))
        job.active_subscan_index = next_index
        job.proc = None
        if start_next:
            start_active_ffuf_process(job, truncate_log=False)
        else:
            job.subscan_pending = True
            job.task_template = ""
            job.task_done = job.task_total = None
            job.seed_done = 0
            job.seed_total = job.subscans[job.active_subscan_index].estimated_total
            job.pass_started = job.task_started = 0.0
            job.progress_rate = 0.0
            job.last_progress_time = 0.0
        return

    job.retcode = retcode
    job.finished = True
    job.failed = retcode != 0
    job.duration_seconds = job.previous_duration + max(0.0, time.time() - job.started)
    if job.subscans:
        aggregate_recursive_subscan_outputs(job)
    job.result_count = read_result_count(job.out_dir / "result.json")
    if not job.failed:
        job.done_est = job.total
    if job.checkpoint_enabled:
        write_job_state(job, job.out_dir.parent)


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
    if job.seed_urls:
        return len(job.seed_urls)
    try:
        return count_nonempty_lines(job.seeds_file)
    except OSError:
        return None


def build_job_summary(job: FfufJob, output_root: Path, status: str | None = None, resumed: bool = False) -> dict[str, object]:
    """Build a serializable per-job summary."""
    actual_status = status or ("stopped" if job.stopped else "failed" if job.failed else "done")
    if job.checkpoint_enabled:
        progress_done, progress_total = job.done_est, job.total
        errors = sum(item.errors or 0 for item in job.passes if item.status != "running")
        if active_pass(job) and active_pass(job).status == "running":
            errors += job.ffuf_errors or 0
    else:
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
    summary = {
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
        "failure_reason": job.failure_reason,
    }
    if job.checkpoint_enabled:
        summary.update(checkpoint_version=1, passes=[pass_record(item, job.out_dir) for item in job.passes],
                       report_hashes=checked_reports(job.out_dir) if actual_status == "done" else None,
                       has_current_results=bool(job.started or any(item.status == "done" for item in job.passes)))
    return summary


def write_job_state(job: FfufJob, output_root: Path, status: str | None = None, resumed: bool = False) -> dict[str, object]:
    """Persist per-job state to job.json and update the done marker."""
    summary = build_job_summary(job, output_root=output_root, status=status, resumed=resumed)
    job_json = job.out_dir / "job.json"
    done_marker = job.out_dir / ".done"
    if job.checkpoint_enabled and summary["status"] == "done" and (
        not all(item.status == "done" for item in job.passes) or not summary.get("report_hashes")
    ):
        summary["status"] = "failed"
        summary["failure_reason"] = job.failure_reason or "Missing or invalid pass reports"
    if summary["status"] != "done":
        done_marker.unlink(missing_ok=True)
    atomic_write_text(job_json, json.dumps(summary, indent=2, ensure_ascii=False) + "\n")
    if summary["status"] == "done":
        atomic_write_text(done_marker, "done\n")
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
    if summary.get("has_current_results") is False:
        return None
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
        if job.checkpoint_enabled and job.passes[subscan.index - 1].status != "done":
            items = []
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
    """Collect first ffuf result per host/status/size/words for manual review."""
    grouped: dict[str, list[dict[str, str]]] = {}
    seen_by_host: dict[str, set[tuple[str, str, str]]] = {}

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
            words = scalar_text(result_value(item, "words", "content_words", "ContentWords"))
            key = (status, size, words)
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
                    "words": words,
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
            "<span>Uniqueness: host:port + status + size + words</span>"
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


def prepare_job(
    job_spec: JobSpec, args: argparse.Namespace, extensions: list[str] | None, job_id: int = 0,
    *, write_files: bool = True,
) -> FfufJob:
    """Build job metadata, optionally creating the files needed to run it."""
    out_dir = args.output_dir / job_spec.name
    seeds_file = out_dir / "paths.txt"
    seeds_text = "\n".join(job_spec.seed_urls) + "\n"
    if write_files:
        out_dir.mkdir(parents=True, exist_ok=True)
        seeds_file.write_text(seeds_text, encoding="utf-8")
    recursion_depth = getattr(args, "recursion_depth", 0)
    headers = getattr(args, "headers", None) or []
    recursion_strategy = getattr(args, "recursion_strategy", "default")
    per_host_rate = rate_per_host(args.rate, getattr(args, "parallel", 1))
    subscans: list[FfufSubscan] = []

    if len(job_spec.seed_urls) > 1:
        subscan_root = out_dir / "subscans"
        single_seed_total = estimate_single_seed_requests(args.wordlist, extensions)
        used_subscan_names: set[str] = set()
        for index, seed_url in enumerate(job_spec.seed_urls, start=1):
            base_name = f"{index:03d}_{seed_slug(seed_url)}"
            subscan_name = base_name
            if subscan_name in used_subscan_names:
                subscan_name = f"{base_name}_{sha256_text(seed_url)[:8]}"
            used_subscan_names.add(subscan_name)
            subscan_out_dir = subscan_root / subscan_name
            if write_files:
                subscan_out_dir.mkdir(parents=True, exist_ok=True)
            subscan_seeds = subscan_out_dir / "paths.txt"
            if write_files and recursion_depth == 0:
                subscan_seeds.write_text(seed_url + "\n", encoding="utf-8")
            subscan_cmd = build_ffuf_cmd(
                seeds_file=seeds_file if recursion_depth else subscan_seeds,
                wordlist=args.wordlist,
                out_dir=subscan_out_dir,
                rate=per_host_rate,
                headers=headers,
                proxy=args.proxy,
                extensions=extensions,
                follow_redirects=args.follow_redirects,
                recursion_depth=recursion_depth,
                recursion_strategy=recursion_strategy,
                base_url=seed_url if recursion_depth else None,
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
            rate=per_host_rate,
            headers=headers,
            proxy=args.proxy,
            extensions=extensions,
            follow_redirects=args.follow_redirects,
            recursion_depth=recursion_depth,
            recursion_strategy=recursion_strategy,
            base_url=base_url,
        )
        commands = [cmd]
        total = estimate_single_seed_requests(args.wordlist, extensions) * len(job_spec.seed_urls)
        subscan_totals = []

    command_text = "\n".join(shell_lines(commands))
    if write_files:
        (out_dir / "command.txt").write_text(command_text + "\n", encoding="utf-8")
    hashes = build_job_hashes(
        seeds_file=seeds_file, wordlist=args.wordlist, command_text=command_text,
        seeds_text=seeds_text.replace("\n", os.linesep) if not write_files else None,
    )

    job = FfufJob(
        job_id=job_id,
        name=job_spec.name,
        seeds_file=seeds_file,
        out_dir=out_dir,
        total=total,
        rate=per_host_rate,
        cmd=cmd,
        command_text=command_text,
        hashes=hashes,
        stderr_log=out_dir / "ffuf.stderr.log",
        host_key=host_key_from_url(job_spec.seed_urls[0]),
        origin=origin_from_url(job_spec.seed_urls[0]),
        stop_aliases=build_stop_aliases(job_spec.name, job_spec.seed_urls),
        subscans=subscans,
        subscan_total_count=max(1, len(subscans)),
        subscan_totals=subscan_totals,
        seed_urls=list(job_spec.seed_urls),
    )
    job.passes = [FfufPass(item.index, item.seed_url, item.out_dir, item.cmd, item.estimated_total)
                  for item in subscans] if subscans else [FfufPass(1, job_spec.seed_urls[0], out_dir, cmd, total)]
    return job


def parse_extensions(raw: str) -> list[str]:
    """Normalize comma-separated extensions for ffuf's literal suffix expansion."""
    extensions: list[str] = []
    for item in raw.split(","):
        extension = item.strip()
        if not extension:
            continue
        if not extension.startswith("."):
            extension = "." + extension
        extensions.append(extension)
    extensions = dedupe_preserve_order(extensions)
    if not extensions:
        raise argparse.ArgumentTypeError("provide at least one extension, for example: php,bak or .php,.bak")
    return extensions


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
        help="Directory with *_Katana.txt files from KatanaScan.py paths mode. Entries are treated as directory URLs.",
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
        help="Maximum active IPs/hosts; only one origin per host runs at a time. Default: 2",
    )
    parser.add_argument(
        "-r",
        "--rate",
        type=int,
        default=300,
        help="Shared rate budget. Each host gets ceil(rate / parallel), fixed even with idle slots. Default: 300",
    )
    parser.add_argument(
        "-e",
        "--extensions",
        type=parse_extensions,
        default=None,
        help=(
            "Comma-separated extensions, for example: .php,.asp,.aspx. "
            "Leading dots are optional; duplicate extensions are removed (case-sensitive)."
        ),
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
        "-ua",
        "--user-agent",
        type=parse_user_agent,
        help="User-Agent for HTTP requests. Default: ffuf's own value.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and print commands/planned seed files without running ffuf or writing files.",
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
        help="Resume verified completed seed passes when inputs and options match; restart interrupted passes.",
    )
    parser.add_argument(
        "--show-cmds",
        action="store_true",
        help="Print the exact ffuf command for each job before starting.",
    )
    parser.add_argument(
        "--ui",
        choices=("auto", "dashboard", "plain"),
        default="auto",
        help="Terminal display: dashboard on a TTY, plain logs otherwise. Default: auto",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue processing other jobs even if one ffuf job fails.",
    )
    args = parser.parse_args(argv)
    try:
        args.headers = headers_with_user_agent(args.headers, args.user_agent)
    except ValueError as exc:
        parser.error(str(exc))
    return args


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
        f"parallel-hosts={parallel} total-rate={rate} per-host={rate_per_host(rate, parallel)}"
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


def selected_origin_job(
    jobs: list[FfufJob], running: list[FfufJob], waiting: list[FfufJob],
    host: str, job_id: int | None = None,
) -> FfufJob | None:
    """An explicit origin stays selected; otherwise follow the host's active job."""
    host_jobs = [job for job in jobs if job_host_key(job) == host]
    if job_id is not None:
        selected = next((job for job in host_jobs if job.job_id == job_id), None)
        if selected is not None:
            return selected
    return next((job for job in running if job_host_key(job) == host), None) or next(
        (job for job in waiting if job_host_key(job) == host), None
    ) or (host_jobs[-1] if host_jobs else None)


def dashboard_job_state(job: FfufJob, running: list[FfufJob]) -> str:
    if job.finished:
        return "failed" if job.failed else "stopped" if job.stopped else "done"
    if job.subscan_pending:
        return "paused"
    return "running" if job in running else "waiting"


def display_duration(seconds: float | None) -> str:
    if seconds is None:
        return "--"
    seconds = max(0, int(seconds))
    return f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"


def display_text(value: object) -> str:
    """Keep terminal control characters out of untrusted result/URL fields."""
    return "".join(char if char.isprintable() else " " for char in str(value))


def task_progress_text(label: str, done: int | None, total: int | None) -> str:
    if done is None or not total:
        return f"{label}: waiting for statistics"
    fraction = min(1.0, max(0.0, done / total))
    filled = int(fraction * 14)
    return f"{label}: {done:,}/{total:,} {'━' * filled}{'─' * (14 - filled)} {fraction:.0%}"


def build_dashboard(
    jobs: list[FfufJob], running: list[FfufJob], waiting: list[FfufJob],
    finished: list[FfufJob], skipped: int, selected_host: str, parallel: int,
    total_rate: int, messages: list[str], prompt: str, paused: bool,
    *, width: int = 120, height: int = 30, show_log: bool = False,
    selected_job_id: int | None = None, focus: str = "hosts", expanded: bool = False,
    detail_offset: int = 0,
    selected_pass_index: int | None = None,
):
    """Render host/origin navigation and live telemetry without changing jobs."""
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    def text_lines(lines):
        return Text("\n".join(display_text(line) for line in lines), no_wrap=True, overflow="ellipsis")

    groups: dict[str, list[FfufJob]] = {}
    for job in jobs:
        groups.setdefault(job_host_key(job), []).append(job)
    hosts = list(groups)
    share = rate_per_host(total_rate, parallel)
    active = {job_host_key(job) for job in running}
    compact = width < 100
    header = (
        f"Hosts {len(active)}/{parallel} active | Origins {len(finished)}/{len(jobs)} done | Skipped {skipped}\n"
        f"Rate {total_rate}/{parallel} slots = {share}/IP | Rounded max {share * parallel}/s"
    )
    if width >= 140:
        measured = f"{sum(job.progress_rate for job in running):.1f}/s" if any(job.saw_progress for job in running) else "--"
        header += f" | Actual {measured} | Errors {sum(job.ffuf_errors or 0 for job in jobs)}"
    header_height, footer_height = 4, (5 if compact else 4)
    event_height = 0 if expanded else (5 if height < 36 else 6)
    body_height = max(4, height - header_height - event_height - footer_height)
    selected = selected_origin_job(jobs, running, waiting, selected_host, selected_job_id)
    origin_job = selected
    pass_item = selected.passes[selected_pass_index] if selected and selected_pass_index is not None and 0 <= selected_pass_index < len(selected.passes) else None
    host_jobs = groups.get(selected_host, [])
    origin_height = min(7, max(4, body_height // 3))
    if expanded:
        origin_height = 4 if height < 38 else 6

    # Host list and independently selectable origins of that host.
    table = Table(expand=True, box=None, padding=(0, 1))
    for title in ("IP / Host", "State", "Origins", "Limit/s"):
        table.add_column(title, no_wrap=True, overflow="ellipsis")
    host_height = body_height - origin_height if not expanded else body_height
    visible = max(1, host_height - 3)
    index = hosts.index(selected_host) if selected_host in hosts else 0
    offset = max(0, min(index - visible // 2, len(hosts) - visible))
    for host in hosts[offset:offset + visible]:
        host_group = groups[host]
        states = [dashboard_job_state(job, running) for job in host_group]
        state = next((value for value in ("running", "paused", "waiting", "failed", "stopped") if value in states), "done")
        table.add_row(
            Text(("> " if host == selected_host else "  ") + display_text(host)),
            Text(state, style={"running": "green", "failed": "red", "paused": "yellow", "done": "cyan"}.get(state, "")),
            Text(f"{sum(job.finished for job in host_group)}/{len(host_group)}"), Text(str(share)),
            style="bold cyan" if host == selected_host else "",
        )
    origins = Table(expand=True, box=None, show_header=False, padding=(0, 0))
    origins.add_column(no_wrap=True, overflow="ellipsis", ratio=1)
    origins.add_column(no_wrap=True)
    origin_index = host_jobs.index(selected) if selected in host_jobs else 0
    origin_visible = max(1, origin_height - 2)
    origin_offset = max(0, min(origin_index - origin_visible // 2, len(host_jobs) - origin_visible))
    for job in host_jobs[origin_offset:origin_offset + origin_visible]:
        chosen = job is selected
        origins.add_row(
            Text(("> " if chosen else "  ") + f"#{job.job_id} " + display_text(job.origin or job.name)),
            Text(dashboard_job_state(job, running)), style="bold cyan" if chosen else "",
        )
    origins_panel = Panel(origins, title=Text(f"Origins ({origin_index + 1 if host_jobs else 0}/{len(host_jobs)})"),
                          border_style="cyan" if focus == "origins" else "white")

    history = Table(expand=True, box=None, show_header=False, padding=(0, 0))
    history.add_column(no_wrap=True, overflow="ellipsis")
    history_height = max(4, body_height - origin_height)
    pass_index = selected_pass_index if pass_item else (selected.active_subscan_index if selected else 0)
    passes = selected.passes if selected else []
    visible_passes = max(1, (history_height - 2) // 2)
    pass_offset = max(0, min(pass_index - visible_passes // 2, len(passes) - visible_passes))
    for item in passes[pass_offset:pass_offset + visible_passes]:
        chosen = item.index - 1 == pass_index
        path = urlsplit(item.seed_url).path or "/"
        elapsed_pass = max(0.0, time.time() - item.started) if item.status == "running" else item.duration
        history.add_row(Text(("> " if chosen else "  ") + f"#{item.index} {display_text(path)}", style="bold cyan" if chosen else ""))
        history.add_row(Text(f"  {item.status} | {display_duration(elapsed_pass) if item.started else '--'} | {item.result_count} hits"))
    history_panel = Panel(history, title=Text(f"Seed passes ({pass_index + 1 if passes else 0}/{len(passes)})"),
                          border_style="cyan" if focus == "passes" else "white")
    if pass_item and selected:
        selected = inspection_job(selected, selected_pass_index)

    lines = ["Select a host with ↑↓; Tab selects its origins."]
    if selected is not None:
        job = selected
        now = time.time()
        end = job.started + job.duration_seconds - job.previous_duration if job.finished else now
        state = pass_item.status if pass_item else dashboard_job_state(job, running)
        cmd = active_subscan(job).cmd if active_subscan(job) else job.cmd
        template = job.task_template or command_option(cmd, "-u") or "URLFUZZ"
        multi_seed = template == "URLFUZZ" and not job.passes
        seed_count = len(job.seed_urls) or 1
        if job.passes:
            base = job.passes[job.active_subscan_index].seed_url
        elif template == "URLFUZZ":
            base = f"{seed_count} seed URLs (URL × FUZZ)"
        else:
            base = template.removesuffix("FUZZ")
        current = f"{job.ffuf_job_current}/{job.ffuf_job_total} known" if job.ffuf_job_current else "awaiting ffuf"
        speed = f"{job.progress_rate:.1f}/s" if job.task_done is not None and state == "running" and not job.subscan_pending else "--"
        age = f"{max(0, int(end - job.last_progress_time))}s ago" if job.last_progress_time else "awaiting progress"
        if job.finished:
            age = "finished" if state == "done" else state
        elapsed = display_duration(job.previous_duration + end - job.started if job.started else None)
        started = time.strftime("%H:%M:%S", time.localtime(job.started)) if job.started else "--"
        errors = str(job.ffuf_errors) if job.ffuf_errors is not None else "--"
        remaining = max(0, (job.task_total or 0) - (job.task_done or 0))
        fresh_speed = job.progress_rate > 0 and job.last_progress_time and now - job.last_progress_time < 5
        eta = display_duration(remaining / job.progress_rate if fresh_speed and state == "running" else None)
        wordlists = [cmd[index + 1].removesuffix(":FUZZ") for index, arg in enumerate(cmd[:-1])
                     if arg == "-w" and cmd[index + 1].endswith(":FUZZ")]
        depth = command_option(cmd, "-recursion-depth") or "0"
        strategy = command_option(cmd, "-recursion-strategy") or "default"
        lines = [
            f"Origin: {job.origin or job.name}",
            f"{'Pass' if pass_item else 'State'}: {state} | Started: {started} | Elapsed: {elapsed}",
            f"Seed: {base}",
            f"Template: {template}",
            (f"Batch: {seed_count} seeds" if multi_seed else f"Seed pass: {job.active_subscan_index + 1}/{job.subscan_total_count}") + f" | ffuf task: {current}",
            task_progress_text("Task", job.task_done, job.task_total),
            task_progress_text("Batch" if multi_seed else "Seed", job.seed_done if job.task_done is not None else None, job.seed_total),
            task_progress_text("Origin (known)", origin_job.done_est if origin_job.started or origin_job.partial_resumed else None, origin_job.total),
            f"Limit: {job.rate}/s | Actual: {speed} | Errors: {errors} | Task ETA: {eta}",
            f"Last advance: {age} | Pass elapsed: {display_duration(end - job.pass_started if job.pass_started else None)}",
        ]
        if expanded or body_height >= 24:
            lines += [
                f"Wordlist: {', '.join(wordlists) or '--'}",
                f"Extensions: {command_option(cmd, '-e') or 'none'} | Recursion: depth {depth}, {strategy}",
                f"Follow redirects: {'yes' if '-r' in cmd else 'no'} | Task elapsed: {display_duration(end - job.task_started if job.task_started else None)}",
            ]
            lines[-1] += " | Totals may grow"
        else:
            lines[-1] += " | Enter: settings / details"
        if multi_seed and expanded:
            lines.append("Seeds: " + ", ".join(job.seed_urls[:3]) + (" …" if seed_count > 3 else ""))

    # Live matches belong only to the selected origin, including completed passes.
    match_table = Table(expand=True, box=None, padding=(0, 1))
    for title in ("Status", "Bytes", "Words", "Path / redirect"):
        match_table.add_column(title, no_wrap=True, overflow="ellipsis", ratio=1 if title == "Path / redirect" else None)
    detail_height = min(len(lines) + 2, max(6, body_height - 5))
    matches_height = max(4, body_height - detail_height)
    if expanded:
        detail_height = min(len(lines) + 2, max(6, body_height - origin_height - 4))
        matches_height = max(4, body_height - origin_height - detail_height)
    compact_detail_height = 0
    if compact and not expanded:
        compact_detail_height = min(6, body_height - origin_height - 4) if body_height >= 12 else 0
        matches_height = max(4, body_height - origin_height - compact_detail_height)
    recent = selected.recent_matches[-max(1, matches_height - 3):] if selected else []
    for item in recent:
        raw_url = str(item.get("url") or "")
        if selected and raw_url.startswith(selected.origin):
            path = "/" + raw_url[len(selected.origin):]
        else:
            path = raw_url
        redirect = item.get("redirectlocation")
        if redirect:
            path += " → " + str(redirect)
        status = str(item.get("status", "--"))
        match_table.add_row(Text(status, style="green" if status.startswith("2") else "yellow" if status.startswith("3") else "red"),
                            Text(str(item.get("length", "--"))), Text(str(item.get("words", "--"))), Text(display_text(path)))
    hits = (selected.result_count if selected.finished and selected.result_count is not None else selected.live_hits) if selected else 0
    match_content = match_table if recent else Text("No matches yet for this origin.")
    matches_panel = Panel(match_content, title=Text(f"Matches — pass #{pass_item.index}: {hits}" if pass_item else f"Matches — this origin: {hits}"))
    if show_log and selected is not None:
        try:
            if pass_item and pass_item.status == "queued":
                raise FileNotFoundError
            with selected.stderr_log.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                log_start = pass_item.stderr_start if pass_item and pass_item.status == "running" else 0
                handle.seek(max(log_start, handle.tell() - 8192))
                log_lines = ANSI_RE.sub("", handle.read().decode("utf-8", errors="replace")).replace("\r", "\n").replace(":: Progress:", "\n:: Progress:").splitlines()
            log_lines = [line for line in log_lines if line.strip()]
        except OSError:
            log_lines = ["Log will appear when this origin starts."]
        matches_panel = Panel(text_lines(log_lines[-max(1, matches_height - 2):]), title="Selected origin: ffuf stderr")

    root = Layout(name="root", size=max(12, height))
    controls = "↑↓ move | Tab hosts/origins/passes | Enter expand | Esc back | p↵ queue | l↵ logs | s↵ stop IP | Ctrl+C"
    if compact:
        controls = "↑↓ move | Tab focus | Enter expand | Esc back\np↵ queue | l↵ log | s↵ stop IP | Ctrl+C"
    if height < 20:
        root.split_column(
            Layout(Panel(Text(f"Rate {total_rate}/{parallel} = {share}/IP"), title="FFuFScan"), size=3),
            Layout(Panel(text_lines([f"Host: {selected_host}", f"Origin: {selected.origin if selected else '--'}",
                                    "Enlarge terminal for detailed progress."]))),
            Layout(Panel(Text(prompt or "Ctrl+C exits")), size=3),
        )
        return root
    root.split_column(
        Layout(Panel(text_lines(header.splitlines()), title="FFuFScan | QUEUE PAUSED" if paused else "FFuFScan"), size=header_height),
        Layout(name="body"),
        *([] if expanded else [Layout(Panel(text_lines(messages[-max(1, event_height - 2):] or ["Waiting for events..."]), title="Events"), size=event_height)]),
        Layout(Panel(text_lines(controls.splitlines() + ([prompt] if prompt else [])), title="Controls"), size=footer_height),
    )
    page_size = max(1, detail_height - 2)
    detail_offset = min(max(0, detail_offset), max(0, len(lines) - page_size))
    detail_title = selected_host or "Origin details"
    if expanded and len(lines) > page_size:
        detail_title += f" | {detail_offset + 1}-{min(len(lines), detail_offset + page_size)}/{len(lines)} PgUp/PgDn"
    details = Layout(Panel(text_lines(lines[detail_offset:]), title=Text(detail_title)), name="details", size=detail_height)
    matches = Layout(matches_panel, name="matches")
    host_panel = Layout(Panel(table, title=Text(f"Hosts ({len(hosts)})"), border_style="cyan" if focus == "hosts" else "white"))
    if expanded:
        if passes and not compact:
            root["body"].split_column(Layout(origins_panel, size=origin_height), Layout(name="inspection"))
            root["inspection"].split_row(Layout(history_panel, ratio=2), Layout(name="pass_details", ratio=5))
            root["pass_details"].split_column(details, matches)
        else:
            root["body"].split_column(Layout(history_panel if passes else origins_panel, size=origin_height), details, matches)
    elif compact:
        # A narrow terminal remains useful; Enter gives the detailed view.
        root["body"].split_column(
            Layout(origins_panel, size=origin_height),
            *([Layout(Panel(text_lines(lines[:4]), title=Text(selected_host)), size=compact_detail_height)] if compact_detail_height else []),
            matches,
        )
    else:
        root["body"].split_row(Layout(name="navigation", ratio=2), Layout(name="telemetry", ratio=3))
        root["navigation"].split_column(host_panel, Layout(origins_panel, size=origin_height))
        root["telemetry"].split_column(details, matches)
    return root


class FfufDashboard:
    """Optional Rich full-screen view; redirected output remains plain text."""

    def __init__(self, mode: str, jobs: list[FfufJob], parallel: int, rate: int) -> None:
        self.jobs = jobs
        self.parallel = parallel
        self.rate = rate
        self.hosts = list(dict.fromkeys(job_host_key(job) for job in jobs))
        self.selected_host = self.hosts[0] if self.hosts else ""
        self.show_log = False
        self.focus = "hosts"
        self.expanded = False
        self.selected_origins: dict[str, int] = {}
        self.selected_passes: dict[int, int] = {}
        self.detail_offset = 0
        self.enabled = mode != "plain" and sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        self.live = None
        if mode == "dashboard" and not self.enabled:
            raise ValueError("--ui dashboard requires a terminal; use --ui plain for redirected output")
        if self.enabled:
            try:
                from rich.console import Console
                from rich.live import Live
            except ImportError:
                if mode == "dashboard":
                    raise ValueError("Rich is required for --ui dashboard; install the project dependencies") from None
                self.enabled = False
            else:
                self.console = Console()
                self.live = Live(console=self.console, screen=True, auto_refresh=False,
                                 redirect_stdout=False, redirect_stderr=False)

    def start(self) -> None:
        if self.live is not None:
            self.live.start()

    def stop(self) -> None:
        if self.live is not None:
            self.live.stop()

    def move_selection(self, direction: int) -> None:
        self.detail_offset = 0
        if self.focus == "passes":
            job_id = self.selected_origins.get(self.selected_host)
            job = next((item for item in self.jobs if item.job_id == job_id), None)
            if job and job.passes:
                index = self.selected_passes.get(job.job_id, job.active_subscan_index)
                self.selected_passes[job.job_id] = (index + direction) % len(job.passes)
            return
        if self.focus == "origins":
            host_jobs = [job for job in self.jobs if job_host_key(job) == self.selected_host]
            if host_jobs:
                job_id = self.selected_origins.get(self.selected_host)
                index = next((index for index, job in enumerate(host_jobs) if job.job_id == job_id), 0)
                self.selected_origins[self.selected_host] = host_jobs[(index + direction) % len(host_jobs)].job_id
            return
        if self.hosts:
            index = self.hosts.index(self.selected_host)
            self.selected_host = self.hosts[(index + direction) % len(self.hosts)]

    def navigate(self, command: str, running: list[FfufJob], waiting: list[FfufJob]) -> bool:
        """Handle immediate navigation keys independently of scan controls."""
        if command not in {"__up__", "__down__", "__tab__", "__enter__", "__escape__", "__page_up__", "__page_down__"}:
            return False
        if not self.enabled:
            return True
        if command in {"__page_up__", "__page_down__"}:
            self.detail_offset = min(20, max(0, self.detail_offset + (-4 if command == "__page_up__" else 4)))
        elif command == "__escape__":
            self.expanded = False
            self.focus = "hosts"
        elif command in {"__tab__", "__enter__"}:
            self.detail_offset = 0
            selected = selected_origin_job(self.jobs, running, waiting, self.selected_host,
                                           self.selected_origins.get(self.selected_host))
            if selected:
                self.selected_origins[self.selected_host] = selected.job_id
            if command == "__enter__":
                self.expanded = not self.expanded
                self.focus = "passes" if self.expanded and selected and selected.passes else "origins" if self.expanded else "hosts"
            else:
                self.focus = {"hosts": "origins", "origins": "passes", "passes": "hosts"}[self.focus]
                self.expanded = self.focus == "passes"
            if self.focus == "passes" and selected:
                self.selected_passes.setdefault(selected.job_id, selected.active_subscan_index)
        else:
            self.move_selection(-1 if command == "__up__" else 1)
        return True

    def update(self, running, waiting, finished, skipped, messages, prompt, paused) -> None:
        if self.live is not None:
            size = self.console.size
            self.live.update(build_dashboard(
                self.jobs, running, waiting, finished, skipped, self.selected_host,
                self.parallel, self.rate, messages, prompt, paused,
                width=size.width, height=size.height, show_log=self.show_log,
                selected_job_id=self.selected_origins.get(self.selected_host),
                focus=self.focus, expanded=self.expanded,
                detail_offset=self.detail_offset,
                selected_pass_index=self.selected_passes.get(self.selected_origins.get(self.selected_host)) if self.expanded else None,
            ), refresh=True)


def main(argv: list[str] | None = None) -> int:
    """Run parallel ffuf jobs from a URL file or Katana paths directory."""
    args = parse_args(argv)

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
            "Error: -fr with -rd > 0 conflicts with redirect-based recursion (-rs default). "
            "To follow redirects, add -rs greedy; it recurses on every match and may add many requests. "
            "Otherwise remove -fr. No jobs were started.",
            file=sys.stderr,
        )
        return 1

    if not args.dry_run and shutil.which("ffuf") is None:
        print("Error: 'ffuf' was not found in PATH.", file=sys.stderr)
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

    extensions = args.extensions

    if not args.dry_run:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    jobs: list[FfufJob] = []
    skipped_count = 0
    summaries: list[dict[str, object]] = []
    for job_id, spec in enumerate(specs, start=1):
        job = prepare_job(spec, args, extensions, job_id=job_id, write_files=not args.dry_run)
        if args.resume:
            resumed_state = load_resume_state(job.out_dir, job.hashes)
            if resumed_state is not None:
                summaries.append(resumed_state)
                skipped_count += 1
                if args.dry_run:
                    print(f"# Skip {job.name}: matches --resume state")
                continue
            restored = load_partial_resume(job)
            if restored:
                print(f"# Resume {job.name}: {restored}/{len(job.passes)} verified seed passes completed")
                if args.dry_run and restored == len(job.passes):
                    print(f"# Rebuild {job.name} aggregate reports from verified passes; no ffuf requests needed")
        jobs.append(job)
        if args.dry_run:
            print(
                f"# Job {job.job_id}: {job.name}; host={job.host_key}; "
                f"rate={job.rate}; estimated base requests={job.total}"
            )
            print(f"# Planned seed file: {job.seeds_file}")
            for seed_url in spec.seed_urls:
                print(f"#   {seed_url}")
            for index, command in enumerate(job_commands(job)):
                if job.passes[index].status == "done":
                    print(f"# Skip seed pass {index + 1}: verified checkpoint")
                    continue
                if job.subscans and args.recursion_depth == 0:
                    print(f"# Planned seed file: {job.subscans[index].out_dir / 'paths.txt'}")
                    print(f"#   {job.subscans[index].seed_url}")
                print("$ " + shlex.join(command))

    if args.dry_run:
        print(
            f"# Dry run: jobs={len(specs)} run={len(jobs)} skipped={skipped_count}; "
            f"host-slots={args.parallel} total-rate={args.rate} "
            f"per-host={rate_per_host(args.rate, args.parallel)} "
            f"rounded-max={rate_per_host(args.rate, args.parallel) * args.parallel}"
        )
        if args.recursion_depth:
            print("# Recursive discovery can add requests beyond the base estimate.")
        return 0

    if args.show_cmds:
        for job in jobs:
            for index, command in enumerate(job_commands(job)):
                if job.passes[index].status != "done":
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
    try:
        dashboard = FfufDashboard(args.ui, jobs, args.parallel, args.rate)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    console.start()
    interactive_enabled = console.enabled
    last_rendered = 0
    abort_requested = False
    paused = False
    last_plain_update = 0.0
    last_plain_counts: tuple[int, ...] = ()
    interrupted = False
    interrupt_requested = False
    old_sigint = signal.getsignal(signal.SIGINT)

    def request_interrupt(signum, frame):
        nonlocal interrupt_requested
        interrupt_requested = True

    # Handle Ctrl+C at scan-loop boundaries, including while Popen or a state
    # replacement is in progress. Every returned child remains owned/reapable.
    signal.signal(signal.SIGINT, request_interrupt)

    try:
        dashboard.start()
        try:
            while waiting or running:
                if interrupt_requested:
                    raise KeyboardInterrupt
                for command in console.read_commands():
                    if dashboard.navigate(command, running, waiting):
                        continue
                    if command.lower() in {"p", "pause"}:
                        paused = not paused
                        control_messages.append("New passes paused; running ffuf processes continue" if paused else "Queue resumed")
                        continue
                    if command.lower() in {"l", "log"}:
                        dashboard.show_log = not dashboard.show_log
                        continue
                    if command.lower() == "s" and dashboard.enabled:
                        command = "s " + dashboard.selected_host
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

                while waiting and len(running) < args.parallel and not paused:
                    if interrupt_requested:
                        raise KeyboardInterrupt
                    next_index = next_available_job_index(waiting, running)
                    if next_index is None:
                        break
                    job = waiting.pop(next_index)
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
                    control_messages.append(f"{time.strftime('%H:%M:%S')} Start {job.origin} on {job.host_key}, rate={job.rate}")

                for job in list(running):
                    if not job.finished:
                        update_job_progress_from_stderr(job)
                        update_job_matches(job)
                        reap_job(job, start_next=not paused and not interrupt_requested)
                    if not job.finished:
                        continue
                    running.remove(job)
                    finished.append(job)
                    control_messages.append(
                        f"{time.strftime('%H:%M:%S')} {'Failed' if job.failed else 'Done'} {job.origin}; hits={job.result_count}"
                    )
                    if job.failed:
                        failed_jobs.append(job)
                        if not args.keep_going:
                            abort_requested = True
                            for other in list(running):
                                stop_job(other, "fail-fast: another origin failed")
                                other.stopped = False
                                other.failed = True
                                write_job_state(other, args.output_dir, status="aborted")
                                running.remove(other)
                                finished.append(other)
                                aborted_jobs.append(other)
                            waiting.clear()
                            break
                    else:
                        cleanup_ffuf_outputs(job.out_dir)

                if abort_requested:
                    break

                if len(control_messages) > 200:
                    del control_messages[:-200]
                if dashboard.enabled:
                    dashboard.update(running, waiting, finished, skipped_count, control_messages,
                                     console.prompt_line() if interactive_enabled else "", paused)
                else:
                    counts = (len(running), len(waiting), len(finished), len(failed_jobs), len(stopped_jobs), int(paused))
                    is_terminal = sys.stdout.isatty()
                    if is_terminal or counts != last_plain_counts or time.monotonic() - last_plain_update >= 5:
                        if is_terminal:
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
                        if not is_terminal:
                            sys.stdout.write("\n")
                            last_rendered = 0
                        last_plain_counts = counts
                        last_plain_update = time.monotonic()
                time.sleep(0.2)
        except KeyboardInterrupt:
            dashboard.stop()
            print("Interrupted.", file=sys.stderr)
            interrupted = True
    finally:
        try:
            for job in running:
                if job.proc and job.proc.poll() == 0 and not interrupted and not interrupt_requested:
                    reap_job(job, start_next=False)
                    if job.finished:
                        finished.append(job)
                        continue
                if job.proc and job.proc.poll() is None:
                    try:
                        job.proc.terminate()
                        job.proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        job.proc.kill()
                        job.proc.wait(timeout=2)
                    except OSError:
                        pass
                update_job_progress_from_stderr(job)
                update_job_matches(job, drain=True)
                finish_pass(job, "interrupted")
                job.duration_seconds = job.previous_duration + max(0.0, time.time() - job.started)
                aggregate_recursive_subscan_outputs(job)
                job.result_count = read_result_count(job.out_dir / "result.json")
                write_job_state(job, args.output_dir, status="interrupted")
        finally:
            try:
                dashboard.stop()
            finally:
                console.stop()
                signal.signal(signal.SIGINT, old_sigint)
        if last_rendered:
            sys.stdout.write("\n")
            sys.stdout.flush()

    for job in jobs:
        job.checkpoint_enabled = bool(job.passes)
        if job.stopped:
            summaries.append(write_job_state(job, output_root=args.output_dir, status="stopped"))
        elif job.failed and job in aborted_jobs:
            summaries.append(write_job_state(job, output_root=args.output_dir, status="aborted"))
        elif not job.finished:
            summaries.append(write_job_state(job, output_root=args.output_dir, status="interrupted" if job.started else "queued"))
        else:
            summaries.append(write_job_state(job, output_root=args.output_dir))

    write_index_files(args.output_dir, summaries)
    write_unique_paths_html(args.output_dir, summaries)

    if interrupted:
        print(f"Checkpoint saved; resume with the same options and --resume. Reports: {args.output_dir}")
        return 130

    print(
        f"FFUF finished: done={sum(not job.failed and not job.stopped for job in finished)} "
        f"failed={len(failed_jobs)} aborted={len(aborted_jobs)} stopped={len(stopped_jobs)} "
        f"skipped={skipped_count}; reports: {args.output_dir}"
    )

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
