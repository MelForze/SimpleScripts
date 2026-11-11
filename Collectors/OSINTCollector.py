#!/usr/bin/env python3
"""Run the agreed subdomain/DNS collection commands in order."""
from __future__ import annotations

import argparse
import codecs
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import shutil
import select
import shlex
import signal
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from urllib.request import Request, urlopen
import zipfile


@dataclass(frozen=True)
class Step:
    title: str
    command: str
    outputs: tuple[str, ...]
    tools: tuple[str, ...]


PASSIVE_FILES = (
    'subdomains/subdomains_dnsdumpster.txt', 'subdomains/subdomains_crtsh.txt',
    'subdomains/subdomains_subfinder.txt', 'subdomains/subdomains_findomain.txt',
    'subdomains/subdomains_assetfinder.txt', 'subdomains/subdomains_bbot_passive.txt',
)
MANUAL = ('Subdomainfinder', 'Pentest-tool', 'Nmapper', 'SuIP')
STATE_FILE = '.osint/template-state.json'


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def file_hash(path: Path) -> str:
    result = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(65536), b''):
            result.update(chunk)
    return result.hexdigest()


def atomic_text(path: Path, value: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix='.' + path.name, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)


@contextmanager
def project_lock(directory: Path, dry_run: bool):
    path = directory / '.lock'
    if dry_run and not path.exists():
        yield
        return
    if not dry_run:
        directory.mkdir(parents=True, exist_ok=True)
    with path.open('rb' if dry_run else 'a+b') as handle:
        try:
            import fcntl
            fcntl.flock(handle, (fcntl.LOCK_SH if dry_run else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError('Another collector is using this project directory') from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def redact(command: str) -> str:
    # Keep secrets out of plans and progress output, not out of executed commands.
    return re.sub(r'(?i)(X-API-Key:\s*)[^"\s]+', r'\1[REDACTED]', command)


def load_steps() -> dict[str, list[Step]]:
    """The agreed domain-list commands, bundled with the standalone script."""
    return {
        'passive': [
            Step('DNSDumpster',
                 r'''for domain in $(cat top_domains.txt); do curl -fsS -H "X-API-Key: ${DNSDUMPSTER_API_KEY}" "https://api.dnsdumpster.com/domain/$domain" | jq -r '.a[].host'; sleep 2; done | tr '[:upper:]' '[:lower:]' | sort -u > ./subdomains/subdomains_dnsdumpster.txt''',
                 (PASSIVE_FILES[0],), ('curl', 'jq', 'tr', 'sort', 'cat', 'sleep')),
            Step('crt.sh',
                 r'''for domain in $(cat top_domains.txt); do curl -fsS "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value'; sleep 2; done | sed 's/^\*\.//' | tr '[:upper:]' '[:lower:]' | sort -u > ./subdomains/subdomains_crtsh.txt''',
                 (PASSIVE_FILES[1],), ('curl', 'jq', 'sed', 'tr', 'sort', 'cat', 'sleep')),
            Step('Subfinder',
                 'subfinder -dL top_domains.txt -all -o ./subdomains/subdomains_subfinder.txt',
                 (PASSIVE_FILES[2],), ('subfinder',)),
            Step('Findomain',
                 'findomain -f top_domains.txt -u ./subdomains/subdomains_findomain.txt',
                 (PASSIVE_FILES[3],), ('findomain',)),
            Step('Assetfinder',
                 'cat top_domains.txt | assetfinder --subs-only | sort -u > ./subdomains/subdomains_assetfinder.txt',
                 (PASSIVE_FILES[4],), ('assetfinder', 'cat', 'sort')),
            Step('BBOT passive',
                 'docker run --platform linux/amd64 --rm -it --pull=always -v "$PWD":/work -w /work -v "$HOME/.config/bbot/secrets.yml":/root/.config/bbot/secrets.yml:ro blacklanternsecurity/bbot:stable -t top_domains.txt -p subdomain-enum -rf passive -n bbot_passive -o .',
                 ('bbot_passive/subdomains.txt',), ('docker',)),
            Step('Copy BBOT passive',
                 'cp ./bbot_passive/subdomains.txt ./subdomains/subdomains_bbot_passive.txt',
                 (PASSIVE_FILES[5],), ('cp',)),
        ],
        'active': [
            Step('BBOT active',
                 'docker run --platform linux/amd64 --rm -it --pull=always -v "$PWD":/work -w /work -v "$HOME/.config/bbot/secrets.yml":/root/.config/bbot/secrets.yml:ro blacklanternsecurity/bbot:stable -t top_domains.txt -p subdomain-enum -n bbot_active -o .',
                 ('bbot_active/subdomains.txt',), ('docker',)),
            Step('Copy BBOT active',
                 'cp ./bbot_active/subdomains.txt ./subdomains/subdomains_bbot_active.txt',
                 ('subdomains/subdomains_bbot_active.txt',), ('cp',)),
            Step('PureDNS',
                 'puredns bruteforce ~/selflists/dns/biggest_dnslist.txt -d top_domains.txt -r resolvers.txt -w puredns_subdomains.txt --write-massdns puredns_massdns.txt --write-wildcards puredns_wildcards.txt',
                 ('puredns_subdomains.txt', 'puredns_massdns.txt', 'puredns_wildcards.txt'), ('puredns', 'massdns')),
            Step('Copy PureDNS',
                 'cp puredns_subdomains.txt ./subdomains/subdomains_puredns.txt',
                 ('subdomains/subdomains_puredns.txt',), ('cp',)),
            Step('Prepare Domain List',
                 r'''sort -u top_domains.txt ./subdomains/subdomains_*.txt | awk 'NF' > domains_stage.txt''',
                 ('domains_stage.txt',), ('sort', 'awk')),
            Step('DNS Records',
                 'for domain in $(cat domains_stage.txt); do for record in A AAAA CNAME NS MX TXT SOA; do dig "$domain" "$record" +noall +answer; done; done > dns_records.txt',
                 ('dns_records.txt',), ('cat', 'dig')),
            Step('SRV Discovery',
                 'for domain in $(cat domains_stage.txt); do for service in _ldap._tcp _kerberos._tcp _kerberos._udp _sip._tcp _sips._tcp _autodiscover._tcp; do dig "${service}.${domain}" SRV +noall +answer; done; done > srv_records.txt',
                 ('srv_records.txt',), ('cat', 'dig')),
            Step('Extract Hosts from DNS Records',
                 r'''awk '$3 == "IN" {if ($4 == "NS" || $4 == "CNAME") print $5; else if ($4 == "MX") print $6; else if ($4 == "SRV") print $8}' dns_records.txt srv_records.txt | sed 's/\.$//' | tr '[:upper:]' '[:lower:]' | awk 'NF' | sort -u > dns_hosts_candidates.txt''',
                 ('dns_hosts_candidates.txt',), ('awk', 'sed', 'tr', 'sort')),
            Step('Reverse DNS / PTR',
                 r'''awk '$3 == "IN" && $4 == "A" {print $5}' dns_records.txt | sort -u | dnsx -ptr -resp-only -silent -rl 100 | sed 's/\.$//' | tr '[:upper:]' '[:lower:]' | sort -u > ptr_hosts_candidates.txt''',
                 ('ptr_hosts_candidates.txt',), ('awk', 'sort', 'dnsx', 'sed', 'tr')),
            Step('Collect DNS Findings',
                 r'''awk 'NR == FNR {root = tolower($1); sub(/\.$/, "", root); if (root != "") roots[root] = 1; next} {for (root in roots) if ($0 == root || substr($0, length($0) - length(root)) == "." root) {print; next}}' top_domains.txt dns_hosts_candidates.txt ptr_hosts_candidates.txt | sort -u > ./subdomains/subdomains_dns_extra.txt''',
                 ('subdomains/subdomains_dns_extra.txt',), ('awk', 'sort')),
            Step('Prepare AXFR',
                 r'''awk 'NR == FNR {root = tolower($1); sub(/\.$/, "", root); if (root != "") roots[root] = 1; next} $3 == "IN" && $4 == "NS" {zone = tolower($1); sub(/\.$/, "", zone); for (root in roots) if (zone == root || substr(zone, length(zone) - length(root)) == "." root) {print $1, $5; next}}' top_domains.txt dns_records.txt | sort -u > dns_zones_ns.txt''',
                 ('dns_zones_ns.txt',), ('awk', 'sort')),
            Step('AXFR',
                 'while read -r zone ns; do dig @"$ns" "$zone" AXFR; done < dns_zones_ns.txt > axfr_result.txt 2>&1',
                 ('axfr_result.txt',), ('dig',)),
            Step('Collect AXFR',
                 r'''awk '$3 == "IN" && $4 ~ /^(A|AAAA|CNAME)$/ && $1 !~ /\*/ {print $1}' axfr_result.txt | sed 's/\.$//' | tr '[:upper:]' '[:lower:]' | sort -u > ./subdomains/subdomains_axfr.txt''',
                 ('subdomains/subdomains_axfr.txt',), ('awk', 'sed', 'tr', 'sort')),
            Step('Final domain collection',
                 r'''awk 'NR==FNR {if (NF) {roots[$0]=1; print}; next} NF {for (d in roots) if ($0==d || (length($0)>length(d) && substr($0,length($0)-length(d))=="."d)) {print; break}}' top_domains.txt ./subdomains/subdomains_*.txt | sort -u > domains.txt''',
                 ('domains.txt',), ('awk', 'sort')),
            Step('Resolve domains to IPv4',
                 r'''while IFS= read -r domain; do host -t A "$domain" | awk -v dom="$domain" '$2 == "has" && $3 == "address" {print dom " - " $4}'; done < domains.txt | sort -u > domains_resolved.txt''',
                 ('domains_resolved.txt',), ('host', 'awk', 'sort')),
            Step('Extract unique IPv4 addresses',
                 r'''awk '{print $3}' domains_resolved.txt | sort -u > scope_ips.txt''',
                 ('scope_ips.txt',), ('awk', 'sort')),
        ],
    }


def config_help() -> str:
    home = Path.home()
    if sys.platform == 'darwin':
        base = home / 'Library/Application Support'
    elif os.name == 'nt':
        base = Path(os.environ.get('APPDATA') or home / 'AppData/Roaming')
    else:
        base = Path(os.environ.get('XDG_CONFIG_HOME') or home / '.config')
    defaults = {'config': str(base / 'subfinder/config.yaml'),
                'provider-config': str(base / 'subfinder/provider-config.yaml')}
    origin = 'OS default (estimate; installed subfinder -h is authoritative)'
    # Ask the installed binary instead of assuming its version uses OS defaults.
    binary = shutil.which('subfinder')
    if binary:
        try:
            result = subprocess.run([binary, '-h'], capture_output=True, text=True, timeout=5)
            output = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout + result.stderr)
            found = {}
            for line in output.splitlines():
                for flag in defaults:
                    if re.search(r'(?:^|[ ,])-' + flag + r'\s', line):
                        match = re.search(r'\(default "([^"]+)"\)', line)
                        if match:
                            found[flag] = match.group(1)
            defaults.update(found)
            if len(found) == 2:
                origin = 'installed subfinder -h'
        except (OSError, subprocess.SubprocessError):
            pass
    for flag, env in [('config', 'SUBFINDER_CONFIG'), ('provider-config', 'SUBFINDER_PROVIDER_CONFIG')]:
        if os.environ.get(env):
            defaults[flag] = os.environ[env]
    def describe(path):
        p = Path(path).expanduser()
        if not p.is_absolute():
            return f'{p} [relative to tool workspace; existence not checked]'
        return f'{p} [{"exists" if p.is_file() else "missing"}]'
    return f'''Local configuration (paths only; key contents are never displayed):
  DNSDumpster:
    Environment: DNSDUMPSTER_API_KEY [{"set" if os.environ.get('DNSDUMPSTER_API_KEY', '').strip() else "missing"}].
    Export your API key before passive/all collection. It is not read from MD.
  Subfinder ({origin}):
    API keys: {describe(defaults['provider-config'])}
    Settings: {describe(defaults['config'])}
    Overrides: SUBFINDER_PROVIDER_CONFIG / SUBFINDER_CONFIG (inherited unchanged).
    Fill provider-config.yaml with your providers' API keys; -all is already
    in the command. Missing keys and API plan limits reduce coverage.
  BBOT (agreed Docker mount):
    API keys: {describe(home / '.config/bbot/secrets.yml')}
    Container: /root/.config/bbot/secrets.yml (read-only).
    Global config: {describe(home / '.config/bbot/bbot.yml')}
    bbot.yml is NOT mounted by the command, so host settings from it do not
    reach Docker. No mounts or command flags are added by the collector.
    Native BBOT config locations do not change this explicit Docker mount.
  Active inputs: ~/selflists/dns/biggest_dnslist.txt and
    ~/selflists/dns/resolvers.txt.
    The resolvers file is copied into each workspace as resolvers.txt.
  Results default to the launch directory; -o selects another directory.
    subdomains/: per-source domain lists, including a copy of PureDNS findings.
    bbot_active/<root>/ and bbot_passive/<root>/: BBOT reports.
    Other result/DNS/PureDNS files: directly in the result directory.
    .osint/: checkpoints and isolated command workspaces.
  Tool installation: --install-tools (no -i; installs missing tools then exits).
    --install-tools --dry-run: offline read-only plan.
    macOS: Homebrew. Linux: Debian/Ubuntu/Kali, Fedora, Arch/Manjaro.
    Architectures: x86_64 / ARM64. Windows: use a supported WSL distribution.
    Existing tools are kept; user binaries go to ~/.local/bin.
    Docker must also be running and accessible; WSL uses Desktop integration.
    Configs/API keys, wordlists and resolvers are not installed or overwritten.
  Display: --ui auto uses a two-column task/live-output dashboard on a suitable
    terminal with Rich; --ui plain keeps a text log. No keyboard capture:
    subprocess prompts keep using stdin. Ctrl+C stops the current process.
  Commands require Bash/POSIX tools (macOS/Linux, or a matching WSL environment).
  Commands are bundled with this script; no Markdown files are required.
  Domain-list variants are used, including for a single root. PTR uses IPv4
  from dns_records.txt; standalone IP/nets.txt alternatives are not executed.
  AXFR runs at its agreed position in active/all mode, without an opt-in flag.
  --dry-run shows commands with API keys redacted; no files or tools are changed.
'''


def read_roots(path: Path) -> list[str]:
    roots = []
    for raw in path.read_text(encoding='utf-8').splitlines():
        root = raw.strip()
        if not root or root.startswith('#'):
            continue
        if len(root) > 253 or '.' not in root or not re.fullmatch(r'[a-zA-Z0-9.-]+', root) or any(
                not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in root.split('.')):
            raise ValueError(f'Expected a root domain, not a URL/IP: {root!r}')
        if all(label.isdigit() for label in root.split('.')):
            raise ValueError(f'Expected domain, got IP: {root!r}')
        if root not in roots:
            roots.append(root)
    if not roots:
        raise ValueError('The input contains no root domains')
    return roots


class TaskScreen:
    """Two-column terminal display; plain output stays usable without Rich."""
    def __init__(self, title: str, labels: list[str], mode: str = 'auto'):
        self.title, self.labels = title, labels
        self.states = ['waiting'] * len(labels)
        self.details = [''] * len(labels)
        self.current = 0
        self.command = self.cwd = ''
        self.lines = deque(maxlen=300)
        self.partial = ''
        self.carriage = False
        self.live = None
        self.enabled = False
        self.started = time.monotonic()
        terminal = sys.stdout.isatty() and sys.stdin.isatty() and os.environ.get('TERM') != 'dumb'
        size = shutil.get_terminal_size((80, 24))
        if mode == 'plain' or (mode == 'auto' and (not terminal or size.columns < 80 or size.lines < 18)):
            return
        if not terminal:
            raise ValueError('--ui dashboard requires an interactive terminal; use --ui plain')
        try:
            from rich.console import Console
            from rich.layout import Layout
            from rich.live import Live
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
        except ImportError:
            if mode == 'dashboard':
                raise ValueError('Dashboard requires Rich; install the project with its dependencies, or use --ui plain') from None
            return
        self.Console, self.Layout, self.Live = Console, Layout, Live
        self.Panel, self.Table, self.Text = Panel, Table, Text
        self.console = Console()
        self.enabled = True

    def __enter__(self):
        if self.enabled:
            self.live = self.Live(get_renderable=self.render, console=self.console, screen=True,
                                  refresh_per_second=4, redirect_stdout=False, redirect_stderr=False)
            self.live.start(refresh=True)
        return self

    def __exit__(self, kind, value, traceback):
        if self.live:
            if kind:
                self.states[self.current] = 'interrupted' if kind is KeyboardInterrupt else 'failed'
                self.feed(str(value or 'Interrupted') + '\n')
            self.refresh()
            self.live.stop()
            completed = sum(state in ('done', 'cached', 'installed', 'present') for state in self.states)
            print(f'{self.title}: {completed}/{len(self.labels)} completed' + ('; interrupted/failed' if kind else ''), flush=True)

    def log(self, message: str):
        if self.enabled:
            self.feed(message + '\n')
            self.refresh()
        else:
            print(message, flush=True)

    def begin(self, index: int, detail: str = '', command: str = '', cwd: str = ''):
        changed = index != self.current or detail != self.details[index]
        self.current, self.command, self.cwd = index, redact(command), cwd
        self.states[index], self.details[index] = 'running', detail
        if self.enabled and changed:
            self.lines.clear()
            self.partial = ''
            self.carriage = False
        self.refresh()

    def finish(self, index: int, state: str = 'done', detail: str = ''):
        self.states[index] = state
        if detail:
            self.details[index] = detail
        self.refresh()

    def feed(self, text: str):
        key = os.environ.get('DNSDUMPSTER_API_KEY')
        if key:
            text = text.replace(key, '[REDACTED]')
        text = redact(text)
        for char in text:
            if char == '\n':
                self.lines.append(self.partial)
                self.partial = ''
                self.carriage = False
            elif char == '\r':
                self.carriage = True
            elif char not in ('\x00', '\x07'):
                if self.carriage:
                    self.partial = ''
                    self.carriage = False
                self.partial = (self.partial + char)[-16384:]

    def refresh(self):
        if self.live:
            self.live.update(self.render(), refresh=True)

    @contextmanager
    def native_terminal(self):
        """Let sudo/system installers own their normal password dialogs."""
        if self.live:
            self.live.stop()
            print(self.labels[self.current] + ': follow the system installer prompts', flush=True)
        try:
            yield
        finally:
            if self.live:
                self.live.start(refresh=True)

    def render(self):
        height = self.console.size.height
        root = self.Layout()
        root.split_column(self.Layout(name='header', size=3), self.Layout(name='body'), self.Layout(name='footer', size=1))
        elapsed = int(time.monotonic() - self.started)
        root['header'].update(self.Panel(self.Text(f'{self.title} | elapsed {elapsed // 60:02d}:{elapsed % 60:02d}', style='bold cyan')))
        root['body'].split_row(self.Layout(name='tasks', size=min(48, max(32, self.console.size.width // 3 + 2))), self.Layout(name='terminal'))
        table = self.Table.grid(padding=(0, 1), expand=True)
        table.add_column(width=2)
        table.add_column(ratio=1)
        table.add_column(width=12)
        visible = max(3, height - 8)
        start = max(0, min(self.current - visible // 2, len(self.labels) - visible))
        colors = {'running': 'cyan', 'done': 'green', 'installed': 'green', 'present': 'green',
                  'cached': 'blue', 'failed': 'red', 'interrupted': 'yellow', 'planned': 'yellow'}
        for i in range(start, min(len(self.labels), start + visible)):
            state = self.states[i]
            style = colors.get(state, 'dim')
            table.add_row(self.Text('>' if i == self.current else '', style='cyan'),
                          self.Text(self.labels[i].split(': ', 1)[-1], style=style, overflow='ellipsis', no_wrap=True),
                          self.Text(state, style=style))
        root['tasks'].update(self.Panel(table, title='Tasks'))
        metadata = self.Text()
        metadata.append(self.labels[self.current] + '\n', style='bold cyan')
        if self.details[self.current]:
            metadata.append(self.details[self.current] + '\n')
        if self.cwd:
            metadata.append('cwd: ' + self.cwd + '\n', style='dim')
        if self.command:
            metadata.append('$ ' + self.command + '\n', style='dim')
        # Keep room for live output even for long shell pipelines.
        width = max(35, self.console.size.width - min(48, max(32, self.console.size.width // 3 + 2)) - 4)
        metadata_lines = metadata.wrap(self.console, width)[:6]
        body = self.Text('\n').join(metadata_lines)
        body.append('\n' + '─' * min(width, 70) + '\n', style='dim')
        remaining = max(1, height - len(metadata_lines) - 9)
        output = list(self.lines) + ([self.partial] if self.partial else [])
        tail = self.Text.from_ansi('\n'.join(output[-remaining:])) if output else self.Text('Waiting for command output…', style='dim')
        body.append_text(tail)
        root['terminal'].update(self.Panel(body, title='Live terminal'))
        root['footer'].update(self.Text('Ctrl+C: stop | Task list follows the current command | --ui plain: text log', style='dim'))
        return root


def run_process(argv: list[str], workspace: Path, screen: TaskScreen | None = None, env: dict | None = None, own_session: bool = True) -> None:
    env = dict(os.environ if env is None else env, PWD=str(workspace))
    interrupted = False

    def defer_interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    # Own the child before delivering Ctrl+C; otherwise interruption inside
    # Popen can leave a running command without a Python process handle.
    previous = signal.signal(signal.SIGINT, defer_interrupt)
    try:
        child = subprocess.Popen(argv, cwd=workspace, env=env, start_new_session=own_session,
                                 stdout=subprocess.PIPE if screen and screen.enabled else None,
                                 stderr=subprocess.STDOUT if screen and screen.enabled else None)
    finally:
        signal.signal(signal.SIGINT, previous)
    try:
        if interrupted:
            raise KeyboardInterrupt
        if screen and screen.enabled:
            decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
            while True:
                ready, _, _ = select.select([child.stdout], [], [], 0.1)
                if ready:
                    chunk = os.read(child.stdout.fileno(), 4096)
                    if not chunk:
                        break
                    screen.feed(decoder.decode(chunk))
                screen.refresh()
                if child.poll() is not None and not ready:
                    break
            screen.feed(decoder.decode(b'', final=True))
        code = child.wait()
    except BaseException as error:
        signals = [(signal.SIGINT, 10), (signal.SIGTERM, 5), (signal.SIGKILL, 5)] if isinstance(error, KeyboardInterrupt) else [(signal.SIGTERM, 3), (signal.SIGKILL, 3)]
        for sig, seconds in signals:
            try:
                if own_session:
                    os.killpg(child.pid, sig)
                else:
                    child.send_signal(sig)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=seconds)
                break
            except subprocess.TimeoutExpired:
                continue
        # The shell may exit before descendants that ignored SIGINT.
        if own_session:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
        raise
    finally:
        if child.stdout:
            child.stdout.close()
    if code:
        raise RuntimeError(f'Command exited with status {code}; stage was not completed')


def run_command(command: str, workspace: Path, screen: TaskScreen | None = None) -> None:
    run_process([shutil.which('bash') or '/bin/bash', '-c', command], workspace, screen)


GO_TOOLS = {
    'subfinder': 'github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
    'assetfinder': 'github.com/tomnomnom/assetfinder@latest',
    'dnsx': 'github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
    'puredns': 'github.com/d3mondev/puredns/v2@latest',
}


@dataclass(frozen=True)
class InstallHost:
    system: str
    arch: str
    manager: str
    wsl: bool = False


@dataclass(frozen=True)
class InstallTask:
    title: str
    kind: str
    tools: tuple[str, ...] = ()
    commands: tuple[tuple[str, ...], ...] = ()
    module: str = ''


def activate_tool_paths():
    """Make user-installed tools visible to children without editing profiles."""
    paths = os.environ.get('PATH', '').split(os.pathsep)
    for path in (Path.home() / '.local/bin', Path.home() / 'go/bin',
                 Path('/opt/homebrew/bin'), Path('/usr/local/bin'), Path('/usr/local/go/bin'),
                 Path('/opt/homebrew/opt/bind/bin'), Path('/usr/local/opt/bind/bin'),
                 Path('/opt/homebrew/opt/coreutils/libexec/gnubin'), Path('/usr/local/opt/coreutils/libexec/gnubin'),
                 Path('/opt/homebrew/opt/gnu-sed/libexec/gnubin'), Path('/usr/local/opt/gnu-sed/libexec/gnubin'),
                 Path('/opt/homebrew/opt/gawk/libexec/gnubin'), Path('/usr/local/opt/gawk/libexec/gnubin'),
                 Path('/Applications/Docker.app/Contents/Resources/bin')):
        if path.is_dir() and str(path) not in paths:
            paths.append(str(path))
    os.environ['PATH'] = os.pathsep.join(paths)


def install_host() -> InstallHost:
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine().lower())
    if not arch:
        raise ValueError(f'Automatic installation supports x86_64/ARM64, not {platform.machine()}')
    if sys.platform == 'darwin':
        return InstallHost('darwin', arch, 'brew')
    if not sys.platform.startswith('linux'):
        raise ValueError('Native Windows/other OS installation is unsupported; run this collector in Linux/WSL or macOS')
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        raise ValueError('Cannot identify Linux distribution from /etc/os-release') from None
    distro = release.get('ID', '').lower()
    family = set(release.get('ID_LIKE', '').lower().split()) | {distro}
    if family & {'debian', 'ubuntu', 'kali'}:
        manager = 'apt-get'
    elif distro == 'fedora':
        manager = 'dnf'
    elif family & {'arch', 'manjaro'}:
        manager = 'pacman'
    else:
        raise ValueError(f'Automatic installation is unsupported for Linux distribution {distro!r}; install the listed tools manually')
    wsl = bool(os.environ.get('WSL_DISTRO_NAME')) or 'microsoft' in platform.release().lower()
    return InstallHost('linux', arch, manager, wsl)


def required_tools(mode: str) -> list[str]:
    tools = ['bash']
    for phase, steps in load_steps().items():
        if mode in ('all', phase):
            for step in steps:
                for name in step.tools:
                    if name not in tools:
                        tools.append(name)
    return tools


def install_plan(host: InstallHost, mode: str) -> tuple[list[InstallTask], list[str]]:
    required = required_tools(mode)
    missing = [tool for tool in required if not shutil.which(tool)]
    tasks = []
    packages = set()
    package_tools = []
    core = ('cat', 'cp', 'sort', 'tr', 'sleep')
    maps = {
        'brew': {'bash': 'bash', 'curl': 'curl', 'jq': 'jq', 'awk': 'gawk', 'sed': 'gnu-sed', 'dig': 'bind', 'host': 'bind'},
        'apt-get': {'bash': 'bash', 'curl': 'curl', 'jq': 'jq', 'awk': 'gawk', 'sed': 'sed', 'dig': 'dnsutils', 'host': 'bind9-host'},
        'dnf': {'bash': 'bash', 'curl': 'curl', 'jq': 'jq', 'awk': 'gawk', 'sed': 'sed', 'dig': 'bind-utils', 'host': 'bind-utils'},
        'pacman': {'bash': 'bash', 'curl': 'curl', 'jq': 'jq', 'awk': 'gawk', 'sed': 'sed', 'dig': 'bind', 'host': 'bind'},
    }
    for tool in missing:
        if tool in core or tool in maps[host.manager]:
            packages.add('coreutils' if tool in core else maps[host.manager][tool])
            package_tools.append(tool)
    go_missing = [name for name in missing if name in GO_TOOLS]
    if missing and host.system == 'linux':
        if not ssl.create_default_context().cert_store_stats().get('x509_ca'):
            packages.add('ca-certificates')
        for tool, package in [('git', 'git'), ('make', 'make'), ('gcc', 'gcc')]:
            if (go_missing or 'massdns' in missing) and not shutil.which(tool):
                packages.add(package)
    if 'docker' in missing and host.system == 'linux' and not host.wsl:
        packages.update({'apt-get': ('docker.io',), 'dnf': ('moby-engine', 'docker-cli'), 'pacman': ('docker',)}[host.manager])
        package_tools.append('docker')
    if packages:
        prefix = () if host.manager == 'brew' or os.geteuid() == 0 else ('sudo',)
        if host.manager == 'apt-get':
            commands = (prefix + ('apt-get', 'update'), prefix + ('apt-get', 'install', '-y', *sorted(packages)))
        elif host.manager == 'dnf':
            commands = (prefix + ('dnf', 'install', '-y', *sorted(packages)),)
        elif host.manager == 'pacman':
            commands = (prefix + ('pacman', '-S', '--needed', '--noconfirm', *sorted(packages)),)
        else:
            commands = (('brew', 'install', *sorted(packages)),)
        tasks.append(InstallTask('System packages', 'packages', tuple(package_tools), commands))
    if go_missing:
        tasks.append(InstallTask('Go toolchain', 'go'))
        for name in go_missing:
            tasks.append(InstallTask(name, 'go-tool', (name,), module=GO_TOOLS[name]))
    if 'findomain' in missing:
        if host.system == 'darwin':
            tasks.append(InstallTask('Findomain', 'packages', ('findomain',), (('brew', 'install', 'findomain'),)))
        else:
            tasks.append(InstallTask('Findomain', 'findomain', ('findomain',)))
    if 'massdns' in missing:
        if host.system == 'darwin':
            tasks.append(InstallTask('massdns', 'packages', ('massdns',), (('brew', 'install', 'massdns'),)))
        else:
            tasks.append(InstallTask('massdns', 'massdns', ('massdns',)))
    if 'docker' in missing and host.system == 'darwin':
        tasks.append(InstallTask('Docker Desktop', 'packages', ('docker',), (('brew', 'install', '--cask', 'docker-desktop'),)))
    if 'docker' in missing and host.wsl:
        tasks.append(InstallTask('Docker Desktop / WSL integration', 'wsl-docker', ('docker',)))
    if 'docker' in required:
        tasks.append(InstallTask('Docker availability', 'docker-check'))
    return tasks, required


def download(url: str, target: Path):
    request = Request(url, headers={'User-Agent': 'SimpleScripts-OSINTCollector-installer'})
    with urlopen(request, timeout=60) as response, target.open('wb') as handle:
        shutil.copyfileobj(response, handle)


def fetch_json(url: str):
    request = Request(url, headers={'User-Agent': 'SimpleScripts-OSINTCollector-installer'})
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def install_binary(source: Path, target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.' + target.name, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        shutil.copyfile(source, temporary)
        temporary.chmod(0o755)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_go(host: InstallHost, screen: TaskScreen) -> str:
    binary = shutil.which('go')
    if binary:
        try:
            version = subprocess.check_output([binary, 'version'], env=dict(os.environ, GOTOOLCHAIN='local'), timeout=10, text=True)
            match = re.search(r'go(\d+)\.(\d+)', version)
            if match and tuple(map(int, match.groups())) >= (1, 21):
                screen.log(version.strip())
                return binary
        except (OSError, subprocess.SubprocessError):
            pass
    releases = fetch_json('https://go.dev/dl/?mode=json')
    artifact = next((file for release in releases if release.get('stable') for file in release['files']
                     if file['os'] == host.system and file['arch'] == host.arch and file['kind'] == 'archive'), None)
    if not artifact or not re.fullmatch(r'go[0-9.]+', artifact['version']) or not re.fullmatch(r'[a-f0-9]{64}', artifact['sha256']):
        raise RuntimeError(f'No verified stable Go SDK for {host.system}/{host.arch}')
    base = Path.home() / '.local/share/simplescripts/toolchains'
    target = base / artifact['version']
    if (target / 'go/bin/go').is_file():
        return str(target / 'go/bin/go')
    base.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.go-install-', dir=base) as temp:
        temp = Path(temp)
        archive = temp / 'go.tar.gz'
        screen.log(f'Downloading {artifact["filename"]}; verifying SHA-256')
        download('https://go.dev/dl/' + Path(artifact['filename']).name, archive)
        if file_hash(archive) != artifact['sha256']:
            raise RuntimeError('Go SDK SHA-256 mismatch')
        unpacked = temp / 'unpacked'
        unpacked.mkdir()
        with tarfile.open(archive) as bundle:
            for member in bundle:
                destination = unpacked / member.name
                if not destination.resolve().is_relative_to(unpacked.resolve()) or not (member.isdir() or member.isfile()):
                    raise RuntimeError('Unsafe entry in Go SDK archive')
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with bundle.extractfile(member) as source, destination.open('wb') as handle:
                        shutil.copyfileobj(source, handle)
                    destination.chmod(member.mode & 0o777)
        if not (unpacked / 'go/bin/go').is_file():
            raise RuntimeError('Go SDK archive is missing go/bin/go')
        if target.exists():
            raise RuntimeError(f'Incomplete Go SDK already exists: {target}; inspect it before retrying')
        os.replace(unpacked, target)
    return str(target / 'go/bin/go')


def install_tools(mode: str, dry_run: bool, ui_mode: str) -> int:
    host = install_host()
    tasks, required = install_plan(host, mode)
    print(f'Tools: {host.system}/{host.arch} | {host.manager}' + (' | WSL' if host.wsl else ''), flush=True)
    present = [name for name in required if shutil.which(name)]
    print('Already installed: ' + (', '.join(present) or 'none'), flush=True)
    native = any(task.kind == 'packages' for task in tasks)
    if not dry_run and native:
        if not shutil.which(host.manager):
            raise RuntimeError(f'{host.manager} is required; install it first' + (' from https://brew.sh/' if host.manager == 'brew' else ''))
        if host.manager == 'brew' and os.geteuid() == 0:
            raise RuntimeError('Run Homebrew installation as a regular user, not root')
        if host.manager != 'brew' and os.geteuid() != 0:
            if not shutil.which('sudo'):
                raise RuntimeError('Installing OS packages requires sudo or root')
    labels = [task.title for task in tasks] or ['Tools present']
    binary_dir = Path.home() / '.local/bin'
    go = None
    with project_lock(Path.home() / '.local/share/simplescripts/install', dry_run), TaskScreen('OSINT tool installation', labels, ui_mode if not dry_run else 'plain') as screen:
        if not tasks:
            screen.finish(0, 'present')
        for index, task in enumerate(tasks):
            description = '\n'.join(shlex.join(command) for command in task.commands)
            if task.kind == 'go':
                description = f'Use Go >= 1.21, or install a SHA-256-verified official SDK for {host.system}/{host.arch}'
            elif task.kind == 'go-tool':
                description = f'GOBIN={binary_dir} GOTOOLCHAIN=auto go install {task.module}'
            elif task.kind == 'findomain':
                description = 'Official Findomain release: ' + ('findomain-linux.zip' if host.arch == 'amd64' else 'findomain-aarch64.zip')
            elif task.kind == 'massdns':
                description = 'git clone https://github.com/blechschmidt/massdns.git; make; install binary in ' + str(binary_dir)
            elif task.kind == 'docker-check':
                description = 'docker info --format {{.ServerVersion}}'
            elif task.kind == 'wsl-docker':
                description = 'Enable Docker Desktop WSL integration for this distribution'
            screen.begin(index, ', '.join(task.tools), description, str(Path.cwd()))
            screen.log(f'[{"plan" if dry_run else "install"}] {task.title}: {description}')
            if dry_run:
                screen.finish(index, 'planned')
                continue
            if task.kind == 'packages':
                for command in task.commands:
                    if command[0] == 'sudo' or '--cask' in command:
                        with screen.native_terminal():
                            run_process(list(command), Path.cwd(), own_session=False)
                    else:
                        run_process(list(command), Path.cwd(), screen)
                activate_tool_paths()
            elif task.kind == 'go':
                go = ensure_go(host, screen)
            elif task.kind == 'go-tool':
                binary_dir.mkdir(parents=True, exist_ok=True)
                build_env = dict(os.environ, GOBIN=str(binary_dir), GOTOOLCHAIN='auto')
                build_env.pop('GOROOT', None)
                run_process([go, 'install', task.module], Path.cwd(), screen,
                            env=build_env)
                activate_tool_paths()
            elif task.kind == 'findomain':
                asset = 'findomain-linux.zip' if host.arch == 'amd64' else 'findomain-aarch64.zip'
                with tempfile.TemporaryDirectory(prefix='osint-findomain-') as temp:
                    temp = Path(temp)
                    download('https://github.com/Findomain/Findomain/releases/latest/download/' + asset, temp / asset)
                    with zipfile.ZipFile(temp / asset) as bundle:
                        member = next((name for name in bundle.namelist() if Path(name).name == 'findomain' and not name.endswith('/')), None)
                        if not member:
                            raise RuntimeError('Findomain release has no findomain executable')
                        source = temp / 'findomain'
                        source.write_bytes(bundle.read(member))
                        source.chmod(0o755)
                        run_process([str(source), '--help'], temp, screen)
                        install_binary(source, binary_dir / 'findomain')
                activate_tool_paths()
            elif task.kind == 'massdns':
                with tempfile.TemporaryDirectory(prefix='osint-massdns-') as temp:
                    directory = Path(temp) / 'massdns'
                    run_process(['git', 'clone', '--depth', '1', 'https://github.com/blechschmidt/massdns.git', str(directory)], Path(temp), screen)
                    run_process(['make'], directory, screen)
                    install_binary(directory / 'bin/massdns', binary_dir / 'massdns')
                activate_tool_paths()
            elif task.kind == 'wsl-docker':
                raise RuntimeError('Enable Docker Desktop WSL integration, then repeat --install-tools')
            elif task.kind == 'docker-check':
                try:
                    result = subprocess.run(['docker', 'info', '--format', '{{.ServerVersion}}'], capture_output=True, text=True, timeout=10)
                except subprocess.TimeoutExpired:
                    raise RuntimeError('Docker did not respond; start Docker Desktop/Engine and repeat --install-tools') from None
                if result.returncode:
                    screen.log(result.stderr.strip())
                    raise RuntimeError('Docker is installed but unavailable to this user; start Docker Desktop/Engine or configure access, then retry')
                screen.log('Docker server: ' + result.stdout.strip())
            missing = [name for name in task.tools if not shutil.which(name)]
            if missing:
                raise RuntimeError('Installation did not provide executable tools: ' + ', '.join(missing))
            screen.finish(index, 'installed' if task.tools else 'done')
    if not dry_run:
        missing = [name for name in required if not shutil.which(name)]
        if missing:
            raise RuntimeError('Tools still missing: ' + ', '.join(missing))
        print(f'Tools ready. User binaries: {binary_dir}. API configs, wordlists and resolvers still need your own data.', flush=True)
    return 0


class Collector:
    def __init__(self, args, roots: list[str], steps: dict[str, list[Step]], screen: TaskScreen | None = None):
        self.args, self.roots, self.steps = args, roots, steps
        self.screen = screen
        self.output = args.output.resolve()
        self.path = self.output / STATE_FILE
        legacy = self.output / 'template-state.json'
        state_path = self.path if self.path.exists() else legacy
        self.state = json.loads(state_path.read_text()) if state_path.exists() else {'schema': 1, 'jobs': {}}
        if self.state.get('schema') != 1:
            raise ValueError('Unsupported collector state schema')
        self.jobs = self.state['jobs']
        self.current = {}

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        atomic_text(self.path, json.dumps(self.state, indent=2) + '\n')

    def prepare(self, root, phase):
        seed = {}
        if phase == 'active':
            prior = self.current.get((root, 'passive')) or self.jobs.get(root + ':passive')
            if prior and prior.get('status') == 'done':
                directory = self.output / prior['workspace']
                for name in PASSIVE_FILES:
                    if (directory / name).is_file():
                        seed[name] = directory / name
        inputs = {name: file_hash(path) for name, path in seed.items()}
        resolver = Path.home() / 'selflists/dns/resolvers.txt'
        if phase == 'active':
            inputs['resolvers.txt'] = file_hash(resolver) if resolver.is_file() else None
        definition = fingerprint([root, [step.command for step in self.steps[phase]], inputs])
        key = root + ':' + phase
        old = self.jobs.get(key)
        if not self.args.refresh and old and old['definition'] == definition:
            directory = self.output / old['workspace']
            valid = 0
            for index, step in enumerate(self.steps[phase]):
                checkpoint = old.get('steps', {}).get(str(index))
                if not checkpoint or any(not (directory / name).is_file() or
                       file_hash(directory / name) != checkpoint.get(name) for name in step.outputs):
                    break
                valid += 1
            if valid == len(self.steps[phase]):
                self.current[(root, phase)] = old
                return old, valid
            # Retry in a clean workspace. BBOT may otherwise reuse/rename an old
            # scan directory. Copy only the verified prefix's outputs.
        else:
            valid = 0
        relative = f'.osint/runs/{root}/{phase}-{time.time_ns()}'
        job = {'definition': definition, 'workspace': relative, 'steps': {}, 'status': 'pending'}
        self.current[(root, phase)] = job
        if self.args.dry_run:
            return job, valid
        directory = self.output / relative
        (directory / 'subdomains').mkdir(parents=True)
        (directory / 'top_domains.txt').write_text(root + '\n', encoding='utf-8')
        for name, source in seed.items():
            shutil.copyfile(source, directory / name)
        if phase == 'active' and resolver.is_file():
            shutil.copyfile(resolver, directory / 'resolvers.txt')
        if valid:
            for index, step in enumerate(self.steps[phase][:valid]):
                for name in step.outputs:
                    destination = directory / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(self.output / old['workspace'] / name, destination)
                job['steps'][str(index)] = old['steps'][str(index)]
        self.jobs[key] = job
        self.save()
        return job, valid

    def run(self):
        phases = ['passive', 'active'] if self.args.mode == 'all' else [self.args.mode]
        stage_offset = 0
        for phase in phases:
            prepared = {root: self.prepare(root, phase) for root in self.roots}
            # Source first, then roots: preserve the agreed action order.
            for index, step in enumerate(self.steps[phase]):
                if phase == 'passive' and index == 1:
                    self.message('Manual (no commands supplied): ' + ', '.join(MANUAL))
                all_cached = True
                for ordinal, (root, (job, valid)) in enumerate(prepared.items(), 1):
                    cached = index < valid
                    all_cached = all_cached and cached
                    if self.screen:
                        self.screen.begin(stage_offset + index, f'{root} | root {ordinal}/{len(prepared)}',
                                          '' if cached else step.command, '' if cached else str(self.output / job['workspace']))
                    self.message(f'[{phase}] {root}: {step.title} [{"cached" if cached else "planned" if self.args.dry_run else "run"}]')
                    if cached:
                        continue
                    self.message('  ' + redact(step.command))
                    self.message('  cwd: ' + str(self.output / job['workspace']))
                    if self.args.dry_run:
                        continue
                    if step.title == 'DNSDumpster' and not os.environ.get('DNSDUMPSTER_API_KEY', '').strip():
                        raise RuntimeError('DNSDUMPSTER_API_KEY is not set; export your DNSDumpster API key before passive/all collection (see --help)')
                    missing = [name for name in step.tools if not shutil.which(name)]
                    if missing:
                        raise RuntimeError('Missing tools: ' + ', '.join(missing))
                    if step.title.startswith('BBOT '):
                        if not (Path.home() / '.config/bbot/secrets.yml').is_file():
                            raise RuntimeError('Missing BBOT secrets.yml; see --help (Docker mount requires a file)')
                        if not sys.stdin.isatty():
                            raise RuntimeError('BBOT uses docker -it; run from an interactive terminal')
                    if step.title == 'PureDNS':
                        if not (Path.home() / 'selflists/dns/biggest_dnslist.txt').is_file():
                            raise RuntimeError('Missing ~/selflists/dns/biggest_dnslist.txt')
                        if not (self.output / job['workspace'] / 'resolvers.txt').is_file():
                            raise RuntimeError('Missing ~/selflists/dns/resolvers.txt')
                    job['status'] = 'running'
                    self.save()
                    directory = self.output / job['workspace']
                    if self.screen and self.screen.enabled:
                        run_command(step.command, directory, self.screen)
                    else:
                        run_command(step.command, directory)
                    missing_files = [name for name in step.outputs if not (directory / name).is_file()]
                    if missing_files:
                        raise RuntimeError('Expected output files are missing: ' + ', '.join(missing_files))
                    job['steps'][str(index)] = {name: file_hash(directory / name) for name in step.outputs}
                    if index == len(self.steps[phase]) - 1:
                        job['status'] = 'done'
                    self.save()
                if self.screen:
                    self.screen.finish(stage_offset + index, 'cached' if all_cached else 'planned' if self.args.dry_run else 'done',
                                       f'{len(prepared)}/{len(prepared)} roots')
            stage_offset += len(self.steps[phase])
        if not self.args.dry_run:
            self.export()

    def message(self, text: str):
        if self.screen:
            self.screen.log(text)
        else:
            print(text, flush=True)

    def export(self):
        # Aggregate copies; original per-root command outputs remain untouched.
        merged = {}
        for root in self.roots:
            for phase in ('passive', 'active'):
                job = self.jobs.get(root + ':' + phase)
                if not job or job['status'] != 'done':
                    continue
                directory = self.output / job['workspace']
                bbot = directory / f'bbot_{phase}'
                if bbot.is_dir():
                    destination = self.output / f'bbot_{phase}' / root
                    shutil.copytree(bbot, destination, dirs_exist_ok=True, symlinks=True)
                names = {name for step in self.steps[phase] for name in step.outputs}
                for name in names:
                    if name.startswith(('bbot_active/', 'bbot_passive/')):
                        continue
                    path = directory / name
                    if path.is_file():
                        merged.setdefault(name, set()).update(path.read_text(encoding='utf-8').splitlines())
        for name, values in merged.items():
            target = self.output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            atomic_text(target, ''.join(line + '\n' for line in sorted(values) if line.strip()))
        exports = set(merged) | {'top_domains.txt'}
        # Passive-only runs still expose their collected names without inventing
        # a final domain-collection command absent from the passive template.
        if 'domains.txt' in merged:
            atomic_text(self.output / 'domains_new.txt', ''.join(line + '\n' for line in sorted(merged['domains.txt'] - self.before_domains)))
            exports.add('domains_new.txt')
        # Removing a root must not leave its old aggregate files visible when
        # the new scope has no completed active results yet.
        for name in set(self.state.get('exports', ())) - exports:
            if name in {item for phase in self.steps.values() for step in phase for item in step.outputs} | {'domains_new.txt'}:
                (self.output / name).unlink(missing_ok=True)
        # The default output now shares the launch directory with input files.
        # Preserve the user's input verbatim if it is already top_domains.txt.
        if self.args.input.resolve() != (self.output / 'top_domains.txt').resolve():
            atomic_text(self.output / 'top_domains.txt', '\n'.join(self.roots) + '\n')
        self.state['exports'] = sorted(exports)
        self.save()
        self.message(f'Results: {self.output}')


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument('-i', '--input', type=Path, help='Root domains, one per line')
    result.add_argument('-o', '--output', type=Path, default=Path('.'), help='Result directory (default: current directory)')
    result.add_argument('--mode', choices=('passive', 'active', 'all'), default='all', help='Collection stages to run (default: all)')
    result.add_argument('--refresh', action='store_true', help='Rerun selected collection stages for all input roots')
    result.add_argument('--dry-run', action='store_true', help='Read-only collection/installation plan; no tools run or files change')
    result.add_argument('--install-tools', action='store_true', help='Install missing tools for this OS and --mode, then exit; no -i required')
    result.add_argument('--ui', choices=('auto', 'plain', 'dashboard'), default='auto', help='Terminal display (default: auto)')
    return result


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    activate_tool_paths()
    cli = parser()
    if '-h' in argv or '--help' in argv:
        cli.epilog = config_help()
    args = cli.parse_args(argv)
    if args.install_tools and (args.input is not None or args.refresh):
        cli.error('--install-tools is install-only; run collection with -i separately')
    if not args.install_tools and args.input is None:
        cli.error('-i/--input is required for collection')
    try:
        if args.install_tools:
            return install_tools(args.mode, args.dry_run, args.ui)
        if os.name != 'posix':
            raise ValueError('These Bash/Docker commands require a POSIX environment (e.g. WSL)')
        steps = load_steps()
        roots = read_roots(args.input)
        phases = ['passive', 'active'] if args.mode == 'all' else [args.mode]
        labels = [f'{phase}: {step.title}' for phase in phases for step in steps[phase]]
        with project_lock(args.output.resolve() / '.osint', args.dry_run), TaskScreen('OSINT collection', labels, args.ui) as screen:
            collector = Collector(args, roots, steps, screen)
            old_domains = args.output / 'domains.txt'
            collector.before_domains = set(old_domains.read_text().splitlines()) if old_domains.exists() else set()
            collector.run()
        if screen.enabled and not args.dry_run:
            print(f'Results: {args.output.resolve()}', flush=True)
        return 0
    except KeyboardInterrupt:
        print('\nInterrupted; completed stages are retained. Repeat the same command to continue.', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f'Error: {redact(str(error))}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
