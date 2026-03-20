#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


KATANA_SUFFIX = "_Katana.txt"
PROGRESS_RE = re.compile(r"Progress:\s*\[(\d+)/(\d+)\]")
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
    if path != "/":
        path = path.rstrip("/") or "/"

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
    return resumed_state


def estimate_total_requests(paths_file: Path, wordlist: Path, extensions: list[str] | None) -> int:
    """Estimate ffuf request count from path count, wordlist size, and extensions."""
    paths_count = count_nonempty_lines(paths_file)
    words_count = count_nonempty_lines(wordlist)
    multiplier = 1 + (len(extensions) if extensions else 0)
    return paths_count * words_count * multiplier


def print_job_line(
    idx: int,
    name: str,
    done: int,
    total: int,
    rate: float,
    state: str,
    elapsed_seconds: int,
) -> None:
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
    print(
        f"  [{idx}] {name:<30} {state:<8} [{bar}] {percent:3d}%  "
        f"({done}/{total}) ETA {eta_text} Elapsed {elapsed_text} Rate {rate_text}"
    )


def clear_lines(count: int) -> None:
    if count <= 0:
        return
    sys.stdout.write("\x1b[1F" * count)
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


def build_ffuf_cmd(
    seeds_file: Path,
    wordlist: Path,
    out_dir: Path,
    rate: int,
    headers: list[str],
    proxy: str | None,
    extensions: list[str] | None,
    follow_redirects: bool,
) -> list[str]:
    """Build an ffuf command for one job."""
    cmd = [
        "ffuf",
        "-c",
        "-w",
        f"{seeds_file}:URL",
        "-w",
        f"{wordlist}:FUZZ",
        "-u",
        "URLFUZZ",
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
    return cmd


@dataclass
class FfufJob:
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


def run_ffuf_background(job: FfufJob) -> None:
    """Start ffuf for one job in the background."""
    job.started = time.time()
    stderr_handle = job.stderr_log.open("w", encoding="utf-8")
    job.proc = subprocess.Popen(
        job.cmd,
        stdout=subprocess.DEVNULL,
        stderr=stderr_handle,
        text=True,
    )
    stderr_handle.close()


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

    job.progress_offset += len(chunk)
    text = chunk.decode("utf-8", errors="ignore").replace("\r", "\n")
    combined = job.progress_remainder + text
    lines = combined.split("\n")

    if combined and not combined.endswith("\n"):
        job.progress_remainder = lines.pop()
    else:
        job.progress_remainder = ""

    for line in lines:
        match = PROGRESS_RE.search(line)
        if not match:
            continue
        now = time.time()
        current = int(match.group(1))
        total = int(match.group(2))
        if total > 0:
            job.total = total
            job.done_est = max(job.done_est, current)
            job.saw_progress = True
        if current > job.last_progress_value:
            if job.last_progress_time > 0:
                delta_time = now - job.last_progress_time
                if delta_time > 0:
                    job.progress_rate = (current - job.last_progress_value) / delta_time
            job.last_progress_value = current
            job.last_progress_time = now

    return True


def reap_job(job: FfufJob) -> None:
    """Update job completion state from the child process."""
    if job.finished or not job.proc:
        return
    retcode = job.proc.poll()
    if retcode is None:
        return
    job.retcode = retcode
    job.finished = True
    job.failed = retcode != 0
    job.duration_seconds = max(0.0, time.time() - job.started)
    job.done_est = job.total
    job.result_count = read_result_count(job.out_dir / "result.json")


def cleanup_ffuf_outputs(out_dir: Path) -> None:
    """Keep result.json/html/md/csv, remove only extra ffuf sidecar formats."""
    for ext in EXTRA_RESULT_EXTENSIONS:
        candidate = out_dir / f"result{ext}"
        if candidate.exists():
            try:
                candidate.unlink()
            except OSError:
                pass


def build_job_summary(job: FfufJob, output_root: Path, status: str | None = None, resumed: bool = False) -> dict[str, object]:
    """Build a serializable per-job summary."""
    actual_status = status or ("failed" if job.failed else "done")
    outputs = {
        "json": relpath_or_absolute(output_root, job.out_dir / "result.json"),
        "html": relpath_or_absolute(output_root, job.out_dir / "result.html"),
        "md": relpath_or_absolute(output_root, job.out_dir / "result.md"),
        "csv": relpath_or_absolute(output_root, job.out_dir / "result.csv"),
        "stderr_log": relpath_or_absolute(output_root, job.stderr_log),
        "command": relpath_or_absolute(output_root, job.out_dir / "command.txt"),
    }
    return {
        "name": job.name,
        "status": actual_status,
        "resumed": resumed,
        "exit_code": job.retcode,
        "duration_seconds": round(job.duration_seconds, 3),
        "result_count": job.result_count,
        "paths_file": relpath_or_absolute(output_root, job.seeds_file),
        "outputs": outputs,
        "hashes": job.hashes,
        "command": job.command_text,
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
        "| Job | Status | Hits | Exit | Duration | JSON | HTML | MD | CSV |",
        "| --- | --- | ---: | ---: | ---: | --- | --- | --- | --- |",
    ]
    for item in ordered:
        outputs = item.get("outputs", {})
        outputs = outputs if isinstance(outputs, dict) else {}
        hits = item.get("result_count")
        hits_text = "-" if hits is None else str(hits)
        exit_code = item.get("exit_code")
        exit_text = "-" if exit_code is None else str(exit_code)
        duration = item.get("duration_seconds")
        duration_text = "-" if duration is None else str(duration)
        lines.append(
            "| {job} | {status} | {hits} | {exit_code} | {duration} | {json_path} | {html_path} | {md_path} | {csv_path} |".format(
                job=item.get("name", "-"),
                status=item.get("status", "-"),
                hits=hits_text,
                exit_code=exit_text,
                duration=duration_text,
                json_path=outputs.get("json", "-"),
                html_path=outputs.get("html", "-"),
                md_path=outputs.get("md", "-"),
                csv_path=outputs.get("csv", "-"),
            )
        )
    (output_root / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def prepare_job(job_spec: JobSpec, args: argparse.Namespace, extensions: list[str] | None) -> FfufJob:
    """Create job files and runtime metadata."""
    out_dir = args.output_dir / job_spec.name
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds_file = out_dir / "paths.txt"
    seeds_file.write_text("\n".join(job_spec.seed_urls) + "\n", encoding="utf-8")

    cmd = build_ffuf_cmd(
        seeds_file=seeds_file,
        wordlist=args.wordlist,
        out_dir=out_dir,
        rate=args.rate,
        headers=args.headers or [],
        proxy=args.proxy,
        extensions=extensions,
        follow_redirects=args.follow_redirects,
    )
    command_text = shlex.join(cmd)
    (out_dir / "command.txt").write_text(command_text + "\n", encoding="utf-8")
    hashes = build_job_hashes(seeds_file=seeds_file, wordlist=args.wordlist, command_text=command_text)

    total = estimate_total_requests(seeds_file, args.wordlist, extensions)
    return FfufJob(
        name=job_spec.name,
        seeds_file=seeds_file,
        out_dir=out_dir,
        total=total,
        rate=args.rate,
        cmd=cmd,
        command_text=command_text,
        hashes=hashes,
        stderr_log=out_dir / "ffuf.stderr.log",
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
        "--rate",
        type=int,
        default=300,
        help="ffuf -rate value for each job. Default: 300",
    )
    parser.add_argument(
        "--extensions",
        type=str,
        default=None,
        help="Comma-separated extension list for ffuf -e, for example: php,asp,aspx",
    )
    parser.add_argument(
        "--header",
        dest="headers",
        action="append",
        help='Additional ffuf header, repeat as needed. Example: --header "Cookie: name=value"',
    )
    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="Proxy to pass to ffuf -x, for example: http://127.0.0.1:8080",
    )
    parser.add_argument(
        "-r",
        "--follow-redirects",
        action="store_true",
        help="Pass -r to ffuf to follow redirects.",
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
    skipped_count: int,
    total_jobs: int,
    parallel: int,
    rate: int,
) -> int:
    """Render the current ffuf job table and return line count."""
    print(
        f"FFUF: total={total_jobs} done={finished_count} failed={failed_count} "
        f"skipped={skipped_count} running={len(running)} waiting={waiting_count} "
        f"parallel={parallel} rate={rate}"
    )
    print()
    if not running and waiting_count == 0:
        print("  all jobs finished")
        return 1
    for idx, job in enumerate(running, start=1):
        print_job_line(
            idx,
            job.name,
            job.done_est,
            job.total,
            job.progress_rate,
            "running",
            int(max(0.0, time.time() - job.started)),
        )
    return max(1, len(running))


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
    for spec in specs:
        job = prepare_job(spec, args, extensions)
        if args.resume:
            resumed_state = load_resume_state(job.out_dir, job.hashes)
            if resumed_state is not None:
                summaries.append(resumed_state)
                skipped_count += 1
                continue
        jobs.append(job)

    if args.show_cmds:
        for job in jobs:
            print("$ " + shlex.join(job.cmd))

    if not jobs:
        write_index_files(args.output_dir, summaries)
        print("All jobs were skipped by --resume.", file=sys.stderr)
        return 0

    waiting = jobs.copy()
    running: list[FfufJob] = []
    finished: list[FfufJob] = []
    failed_jobs: list[FfufJob] = []
    aborted_jobs: list[FfufJob] = []
    header_lines = 2
    last_rendered = 0
    abort_requested = False

    print()
    print(
        f"FFUF: total={len(jobs) + skipped_count} done=0 failed=0 skipped={skipped_count} "
        f"running=0 waiting={len(waiting)} parallel={args.parallel} rate={args.rate}"
    )
    print()

    try:
        while waiting or running:
            while waiting and len(running) < args.parallel:
                job = waiting.pop(0)
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

            clear_lines(last_rendered + header_lines)
            last_rendered = render_status(
                running=running,
                waiting_count=len(waiting),
                finished_count=len(finished),
                failed_count=len(failed_jobs),
                skipped_count=skipped_count,
                total_jobs=len(jobs) + skipped_count,
                parallel=args.parallel,
                rate=args.rate,
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

    for job in finished:
        if job.failed and job in aborted_jobs:
            summaries.append(write_job_state(job, output_root=args.output_dir, status="aborted"))
        else:
            summaries.append(write_job_state(job, output_root=args.output_dir))

    write_index_files(args.output_dir, summaries)

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
