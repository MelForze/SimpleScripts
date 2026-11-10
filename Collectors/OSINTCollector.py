#!/usr/bin/env python3
"""Run the agreed subdomain/DNS collection commands in order."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time


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


def run_command(command: str, workspace: Path) -> None:
    env = dict(os.environ, PWD=str(workspace))
    interrupted = False

    def defer_interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    # Own the child before delivering Ctrl+C; otherwise interruption inside
    # Popen can leave a running command without a Python process handle.
    previous = signal.signal(signal.SIGINT, defer_interrupt)
    try:
        child = subprocess.Popen([shutil.which('bash') or '/bin/bash', '-c', command],
                                 cwd=workspace, env=env, start_new_session=True)
    finally:
        signal.signal(signal.SIGINT, previous)
    try:
        if interrupted:
            raise KeyboardInterrupt
        code = child.wait()
    except KeyboardInterrupt:
        for sig, seconds in [(signal.SIGINT, 10), (signal.SIGTERM, 5), (signal.SIGKILL, 5)]:
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=seconds)
                break
            except subprocess.TimeoutExpired:
                continue
        # The shell may exit before descendants that ignored SIGINT.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
        raise
    if code:
        raise RuntimeError(f'Command exited with status {code}; stage was not completed')


class Collector:
    def __init__(self, args, roots: list[str], steps: dict[str, list[Step]]):
        self.args, self.roots, self.steps = args, roots, steps
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
        for phase in phases:
            prepared = {root: self.prepare(root, phase) for root in self.roots}
            # Source first, then roots: preserve the agreed action order.
            for index, step in enumerate(self.steps[phase]):
                if phase == 'passive' and index == 1:
                    print('Manual (no commands in template): ' + ', '.join(MANUAL), flush=True)
                for root, (job, valid) in prepared.items():
                    cached = index < valid
                    print(f'[{phase}] {root}: {step.title} [{"cached" if cached else "planned" if self.args.dry_run else "run"}]', flush=True)
                    if cached:
                        continue
                    print('  ' + redact(step.command), flush=True)
                    print('  cwd: ' + str(self.output / job['workspace']), flush=True)
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
                    run_command(step.command, directory)
                    missing_files = [name for name in step.outputs if not (directory / name).is_file()]
                    if missing_files:
                        raise RuntimeError('Expected output files are missing: ' + ', '.join(missing_files))
                    job['steps'][str(index)] = {name: file_hash(directory / name) for name in step.outputs}
                    if index == len(self.steps[phase]) - 1:
                        job['status'] = 'done'
                    self.save()
        if not self.args.dry_run:
            self.export()

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
        print(f'Results: {self.output}', flush=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument('-i', '--input', required=True, type=Path, help='Root domains, one per line')
    result.add_argument('-o', '--output', type=Path, default=Path('.'), help='Result directory (default: current directory)')
    result.add_argument('--mode', choices=('passive', 'active', 'all'), default='all', help='Collection stages to run (default: all)')
    result.add_argument('--refresh', action='store_true', help='Rerun selected collection stages for all input roots')
    result.add_argument('--dry-run', action='store_true', help='Read-only command plan; API keys are redacted')
    return result


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    cli = parser()
    if '-h' in argv or '--help' in argv:
        cli.epilog = config_help()
    args = cli.parse_args(argv)
    try:
        if os.name != 'posix':
            raise ValueError('These Bash/Docker commands require a POSIX environment (e.g. WSL)')
        steps = load_steps()
        roots = read_roots(args.input)
        with project_lock(args.output.resolve() / '.osint', args.dry_run):
            collector = Collector(args, roots, steps)
            old_domains = args.output / 'domains.txt'
            collector.before_domains = set(old_domains.read_text().splitlines()) if old_domains.exists() else set()
            collector.run()
        return 0
    except KeyboardInterrupt:
        print('\nInterrupted; completed stages are retained. Repeat the same command to continue.', file=sys.stderr)
        return 130
    except (OSError, ValueError, RuntimeError) as error:
        print(f'Error: {redact(str(error))}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
