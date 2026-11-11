<div align="center">
  <a href="https://ibb.co/mcnkMm2">
    <img src="https://i.ibb.co/2kzxfwC/2024-09-12-20-11-35.jpg" alt="2024-09-12-20-11-35" width="280">
  </a>
  <h2>Simple Scripts</h2>
</div>

This repository consists of scripts that can make life easier for both me and you by helping with information gathering and structuring.

## Installation

### pipx

You can install the repository directly with `pipx`:

```bash
pipx ensurepath
pipx install git+https://github.com/MelForze/SimpleScripts.git
```

For local development / local checkout:

```bash
pipx install .
```

To refresh an existing installation from the repository:

```bash
pipx upgrade simplescripts
```

## Collectors

KatanaScan and FFuFScan accept `--user-agent` (or `-ua`) and `--dry-run`:

```bash
KatanaScan.py -i targets.txt -m everything --user-agent "MyAudit/1.0" --dry-run
FFuFScan.py --paths-dir katana/paths -w words.txt --user-agent "MyAudit/1.0" --dry-run
```

Remove `--dry-run` to run the commands. Dry runs validate inputs and print commands
and output paths without starting the tools or creating/modifying result files.
FFuFScan also prints planned seed-file contents and checks `--resume` state without
changing it. The underlying binaries are not required for a dry run.

Without `--user-agent`, the tools keep their own defaults. Explicit UA values must
be non-empty and agree with any `User-Agent` passed through `--header`.
With a custom UA, KatanaScan uses Katana's hybrid browser engine for `--browser`:
the v1.8.0 pure headless engine overwrites Chromium's launch-time UA with a default
device profile. Without a custom UA, `--browser` keeps using the headless engine.
In Katana v1.8.0, the built-in robots.txt/sitemap.xml fetchers set their own UA
independently.

FFuFScan merges input files by origin and schedules them by IP/host. Different
ports or schemes on the same IP run sequentially; up to `-p` independent hosts
can run in parallel. DNS names are grouped by hostname without DNS resolution.
`-r` is now a shared budget: each host gets a fixed `ceil(r / p)` limit, even when
some slots are idle. For example, `-p 5 -r 1000` gives 200/s per host; `-p 3 -r 1000`
gives 334/s each (1002/s across three occupied slots due to rounding). This is
ffuf's request-rate limit; following redirects can add HTTP exchanges.

On a terminal, FFuFScan displays host queues, the origins of the selected host,
and live details for the selected origin. Use `--ui plain` for text output or
`--ui dashboard` to require the full-screen view.

- Arrow keys select a host. Tab cycles through hosts, origins and seed passes;
  arrow keys select an item in the focused list.
- Enter expands origin details with its seed-pass history. A selected pass shows
  its own status, elapsed time, matches and log, including completed passes.
  Esc returns to the host view. PgUp/PgDn scroll details on small terminals.
- `p` + Enter pauses/resumes new jobs and seed passes. Already-running ffuf
  processes, including their internal recursive jobs, continue during a pause.
- `l` + Enter toggles the selected origin's live matches/stderr panel.
- `s` + Enter stops the selected **host and all its queued origins**, including
  while inspecting one origin. `s <id|host>` + Enter targets a job ID or host.

Details distinguish the current ffuf task, the seed pass, and the entire origin.
Each seed runs as a separate sequential pass, including without recursion, so
completed seeds can be resumed independently. The request URL/prefix semantics
remain the same; starting ffuf for every seed adds process startup overhead.
Expanded details include the wordlist, extensions,
recursion/redirect settings, elapsed times, rate, errors and estimated time left
for the current task. Statistics show as pending until ffuf reports them. Known
totals can grow when ffuf discovers recursive jobs; task ETA is approximate.

Matches arrive during the scan with status, bytes, words, URL path and redirect
location. The count and recent rows belong to the selected origin, across its
seed passes. ffuf's JSONL stdout is saved as `ffuf.matches.jsonl` in each origin's
directory; the dashboard retains the latest 100 matches per origin and per pass
in memory. Completed passes have their own logs in `subscans/`. Final
`result.json/html/md/csv` reports remain available. Redirected output uses plain
logs. Both carriage-return and concatenated ffuf progress updates are supported.

FFuFScan writes `job.json` checkpoints atomically when a seed starts or finishes.
Ctrl+C terminates/reaps running children, marks unfinished work as interrupted,
and writes the summary reports. Completed passes also survive an abrupt parent
process exit. Add `--resume` to the same command to reuse completed passes:
paths, wordlist and command-option hashes must match, and all four pass reports
must pass integrity checks. Empty match sets are valid completed passes.
Interrupted/failed passes restart from their beginning, including ffuf's internal
recursive queue; resuming at an exact word is not supported. Without `--resume`,
the command starts a fresh scan. `--resume --dry-run` previews the remaining
commands without changing state or reports. Older whole-origin checkpoints can
still be skipped when their hashes match, but have no per-seed recovery history.
The origin's `.done` marker is created only after every pass and its combined
reports have been validated. Missing combined reports can be rebuilt from
verified completed passes without sending the requests again.

`-fr` with `-rd > 0` and the default recursion strategy is rejected before any
jobs start. Add `-rs greedy` explicitly to combine recursion with redirect
following, or remove `-fr` to retain redirect-based directory recursion.

### OSINT collector

`Collectors/OSINTCollector.py` contains the agreed subdomain/DNS commands and
executes them in the established OSINT action order. It is self-contained:
`Passive Actions.md`, `Active Actions.md`, and the `Pentest Template/` directory
are not read or required at runtime. The same commands are bundled in pipx
installations; `--templates` has been removed. The DNSDumpster header reads its key from the environment instead
of embedding a literal key from Markdown; BBOT includes the agreed `-y` flag
for automatic scan-start confirmation.

From the repository root for a local checkout:

```bash
export DNSDUMPSTER_API_KEY="YOUR_API_KEY"
python3 Collectors/OSINTCollector.py --help
python3 Collectors/OSINTCollector.py -i top_domains.txt --dry-run
python3 Collectors/OSINTCollector.py -i top_domains.txt
```

After installing with pipx, run from your scan working directory containing
`top_domains.txt`; no repository checkout or Markdown files are needed there:

```bash
export DNSDUMPSTER_API_KEY="YOUR_API_KEY"
OSINTCollector.py -i top_domains.txt
```

Install missing external tools first, from any working directory:

```bash
OSINTCollector.py --install-tools --dry-run
OSINTCollector.py --install-tools
```

`--install-tools` is an installation-only mode and does not need `-i`. It exits
without starting collection; pass `--mode passive` or `--mode active` to install
only that part's prerequisites. Ordinary collection never installs packages.
Existing executables are reused. Installation supports macOS with Homebrew,
Debian/Ubuntu/Kali with apt, Fedora with dnf, and Arch/Manjaro with pacman, on
x86_64 and ARM64. Unsupported systems/architectures stop with a clear message.
Native Windows must use a supported WSL environment. Homebrew itself must
already be installed. Linux system packages may require sudo. Commands using sudo and native
Docker Desktop installation temporarily use the normal terminal for system
prompts; the dashboard resumes afterward. Passwords are handled by sudo/system
installers and are never captured by the collector.

Subfinder, Assetfinder, dnsx and PureDNS are installed from their upstream Go
modules into `~/.local/bin`. Existing Go >= 1.21 is reused with automatic
upstream toolchain selection; otherwise a matching stable Go SDK is downloaded
from go.dev, checked against the published SHA-256, and installed under
`~/.local/share/simplescripts/toolchains/`. System Go is not replaced. macOS
uses Homebrew for Findomain and massdns; Linux uses the official Findomain
release for its CPU architecture and builds massdns from upstream source.
The collector adds these tool directories to its own process PATH without
editing shell profiles. Use `~/.local/bin` in your shell PATH if you also want
to invoke the newly installed binaries directly.

Docker is installed through the platform package manager (Docker Desktop on
macOS, distro Docker/Moby packages on Linux). WSL instead asks for Docker
Desktop integration, avoiding installation of another engine. A final check
requires a responding Docker server available to the current user; start the
engine/Desktop or configure access if that check fails, then repeat the flag.
The installer does not change Docker groups, socket permissions, API keys,
provider configs, resolver files or wordlists. These still need your own data.
`--install-tools --dry-run` performs no downloads, subprocess execution or writes.

On an interactive terminal with Rich and enough room, both installation and
collection show a two-column dashboard: task states on the left; current root,
command, working directory and live stdout/stderr on the right. Up/Down selects
a task independently of the running task;
PgUp/PgDn scroll its output and `f` returns to following the active task. Each
task keeps its own latest 300 output lines, including after it finishes and
across roots within that stage. Wrapped output is cropped to the actual pane
size; child cursor/title/clipboard controls cannot move or expand the dashboard.
Rendering uses one timer at four frames per second, independently of log volume.
In tmux, both ordinary and application-mode arrow sequences are accepted.

Tab switches between task navigation and input to the active tool. Tool input
uses a separate pseudo-terminal so Docker BBOT's `-it` still receives a TTY;
letters such as `f` and arrow keys go to the tool while that mode is selected.
Tab returns to navigation. sudo/system installer prompts temporarily use the
native terminal with the navigation reader stopped; their passwords are not
captured. Terminal attributes are restored on completion, errors and Ctrl+C.
Ctrl+C terminates the owned process group; completed collection stages stay saved.
After a failure, the task name, details, command, cwd and last 20 output lines
are printed outside the alternate screen so the actual stderr is not lost.
Use `--ui plain` for a normal text log, or `--ui dashboard` to explicitly require
the dashboard. Auto mode falls back to plain logs for redirected output, small
terminals, or when Rich is unavailable. Rich is already a project dependency
for normal pipx installations. Task selection changes the viewed history;
per-root workspaces and the dependency group order are preserved. The BBOT confirmation
flag is described below.

Results default to the current launch directory; `-o` selects another result
directory. The default is `--mode all`: passive collection first, then active collection.
`--mode passive` and `--mode active` select one part. Domain-list command variants
are used even for a single domain. Each root gets an isolated workspace with its
own `top_domains.txt`; dependency groups preserve ordering between stages
that consume one another's files. The collector creates the `subdomains/` directory and copies
`~/selflists/dns/resolvers.txt` and `~/selflists/dns/resolvers-trusted.txt` into active
workspaces under those same filenames. Changing either file invalidates the active
cache. The wordlist is also included in the active cache fingerprint. Other
paths and tool options retain their agreed values.

Collection uses a shared queue, with at most **four commands
running globally across all input roots**, and at most **one BBOT** at a time:

1. DNSDumpster, crt.sh, Subfinder, Findomain, Assetfinder and passive BBOT are
   independent queue tasks. Each API command retains its own original pauses.
   PureDNS is queued immediately alongside them in `--mode all`, without
   waiting for passive collection. The manual entries remain visible.
2. BBOT and PureDNS copies wait for their own producers. Once all passive
   outputs for a root are complete, they are attached to its active workspace
   and seeds are prepared. This does not move or interrupt a running PureDNS.
3. Active BBOT can start for that root as soon as its passive snapshot and
   seeds are ready, even while PureDNS or other roots' passive tasks still run.
   The single-BBOT limit also applies across passive and active tasks.
4. Domain-list preparation waits for the discovery queue to finish, including
   both active BBOT and PureDNS. DNS records and SRV share the slots.
5. Later DNS/PTR/AXFR groups, the two expansion rounds and final exports retain
   their established dependency order.

Each source/stage has at most one root running at once; roots share the global
slots rather than multiplying the concurrency limit. Tool command lines,
outputs and internal tool rate settings are unchanged. This can increase
aggregate API traffic compared with the earlier sequential runner; the four-slot
limit is on commands, not on the tools' internal threads/requests.

The dashboard can show several `running` stages. Each command's output is routed
to its own task history, and Tab sends input only to the selected running task.
Switching the viewed task does not move another command's stdin. On a failure,
no new work is launched, already-running peers are stopped/reaped, and dependent
groups do not start. Successful completed checkpoints are saved by the single
coordinator, including independent steps after a failed step. Ctrl+C stops all
slots and preserves completed work. Failed/interrupted commands restart from
their beginning in a clean workspace on the next invocation.

The single-domain, standalone-IP and `nets.txt` alternatives are not run in
addition to the chosen list variants. Company research, leaks, code and job-site
sections are outside this version.

There are no collector-added rates, request retries, timeouts, host limits or
UA overrides. In particular, `dnsx -rl 100`, the API-loop `sleep 2`, BBOT's
`--platform linux/amd64 --rm -it --pull=always`, and PureDNS's wordlist path come
from the agreed commands. AXFR is executed at its established position.
BBOT uses `-y` in both passive and active passes to skip the scan-start
confirmation. This does not add `--force` or change module selection. The agreed
Docker `-it` is retained; terminal input is proxied in dashboard mode. Adding
`-y` does not invalidate completed collection checkpoints.
The commands require Bash/POSIX tools; use macOS/Linux or a matching
WSL environment. Install `curl`, `jq`, `subfinder`, `findomain`, `assetfinder`,
Docker, `puredns`/`massdns`, `dig`, `dnsx`, `host` and the shell text tools.

`--help` displays config paths and file existence without reading key contents:

- DNSDumpster reads `DNSDUMPSTER_API_KEY` from the environment. The help reports
  only whether it is set. Passive/all collection stops with an explicit error
  before the DNSDumpster command if its key is missing; it is not cached as an
  empty success. `--dry-run` and active-only collection do not require this key.
  Keys are not interpolated into stored command strings or checkpoint data.

- Subfinder paths are taken from the installed `subfinder -h` when available,
  respecting `SUBFINDER_CONFIG` and `SUBFINDER_PROVIDER_CONFIG`. Otherwise the
  help displays an explicitly labelled estimate for macOS, Linux/XDG or
  Windows/APPDATA. Fill the providers' API keys in `provider-config.yaml`;
  `-all` is already present in the command. Keys, enabled sources and API plan
  limits affect coverage. Use absolute paths for config environment overrides:
  relative paths are resolved by Subfinder from its per-root workspace.
- BBOT's Docker command mounts `$HOME/.config/bbot/secrets.yml` read-only
  at `/root/.config/bbot/secrets.yml`. Put API keys there. Although native BBOT
  also has `bbot.yml`, the command does **not** mount it; its host settings do
  not reach this container. The collector never adds another mount or changes
  the explicit path based on OS conventions.
- Active collection requires `~/selflists/dns/biggest_dnslist.txt`,
  `~/selflists/dns/resolvers.txt` for bulk queries, and a separate small list in
  `~/selflists/dns/resolvers-trusted.txt` for trusted checks. Put one DNS server
  address per line in each resolver file. PureDNS receives an explicit
  `--resolvers-trusted resolvers-trusted.txt`; the collector checks both files
  before collection and copies them into each active workspace. These input
  files are maintained locally and are not created or overwritten by collection.
  The help lists all required paths.

Before any collection command, a common readiness check reports all detected
problems together: selected binaries and required options, Docker access,
BBOT options, required readable nonempty files, DNSDumpster key presence and
output write access. Missing default Subfinder configs are warnings; explicit
config overrides must be readable absolute paths. Help/version checks do not
scan targets. BBOT's help check uses the same Docker image, platform and
`--pull=always` policy as collection, so it can download/update that image.
Key validity, paid API limits and remote service availability are not tested.
`--dry-run` skips all readiness subprocesses and writes.

Active BBOT receives `-s bbot_seeds.txt`: the root and deduplicated passive
findings inside its original scope. `-t top_domains.txt` continues to define
scope. Active-only runs reuse available passive results, or start with the root
alone. This requires BBOT 3's `--seeds` interface, checked before collection.
After the initial DNS/SRV/PTR/AXFR stages, up to two additional rounds query
new scoped names discovered in those answers. Already queried names, IPv4
addresses and zone/NS pairs are excluded; empty rounds invoke no tools.
Per-round outputs remain under `dns_round_1/` and `dns_round_2/` in the active
workspace and are merged into the usual top-level DNS exports. New findings
from the last round enter final domain lists without a third expansion round.
The final domain collection and IPv4 resolution still run after expansion.

Use the same output directory when adding root domains. Completed stages are
checked against output hashes and reused; new roots are collected separately.
An interrupted/failed command is retried in a clean workspace with copies of
all verified independent completed outputs. Invalidated producer files also
invalidate their dependent copy/processing checkpoints; unrelated successful
providers are reused. Use `--refresh` after changing tool configs or
keys, or to repeat collection. There is one writer per project. New checkpoints
are in `.osint/template-state.json`; legacy `template-state.json` checkpoints
are read if the new state file is absent. The earlier collector's `state.sqlite3` is not
reused because its commands differed. Old data is not deleted.

PureDNS has a separate input fingerprint for the root, command, wordlist and
both resolver files. Its verified completed outputs survive a passive failure
or changed passive results, while seeds and active BBOT use the new passive
snapshot. `--refresh` reruns PureDNS too. This scheduler upgrade recollects
previous active caches once to add the wordlist fingerprint; passive caches
and provider command lines remain unchanged.

`--dry-run` prints a read-only plan without running tools or creating/modifying
project files. API keys are redacted in progress/plans; the actual command is
executed with environment-variable expansion by Bash. Live tool output is shown in the terminal panel or plain log, preserving BBOT's
interactive stdin. A nonzero shell exit or a missing expected output stops
the run (exit 1); Ctrl+C returns 130 and preserves completed checkpoints.
Pipeline exit semantics remain Bash defaults, as in the agreed commands: an
upstream failure can be masked by a successful final pipeline command.

Original command outputs remain under `.osint/runs/<root>/<phase>-<id>/`.
Top-level files aggregate completed workspaces for the input roots:

```text
<launch directory, or -o directory>/
├── top_domains.txt
├── domains.txt
├── domains_new.txt
├── bbot_seeds.txt
├── findings_history.json
├── domains_resolved.txt
├── scope_ips.txt
├── domains_stage.txt
├── dns_records.txt
├── srv_records.txt
├── dns_hosts_candidates.txt
├── ptr_hosts_candidates.txt
├── dns_zones_ns.txt
├── axfr_result.txt
├── puredns_subdomains.txt
├── puredns_massdns.txt
├── puredns_wildcards.txt
├── subdomains/
│   ├── subdomains_subfinder.txt
│   ├── subdomains_puredns.txt
│   └── ...
├── bbot_active/<root>/
├── bbot_passive/<root>/
└── .osint/
    ├── template-state.json
    └── runs/
```

Only the per-source domain lists are in `subdomains/`. Full BBOT reports are
copied to `bbot_active/<root>/` and `bbot_passive/<root>/`, keeping roots separate.
Final lists and intermediate DNS/PureDNS files are directly in the result
directory. An input already named `top_domains.txt` in that directory is kept
verbatim. `domains_new.txt` contains names newly added to the final export by
this invocation; passive-only runs do not invent a final collection stage.
Export copies are deduplicated; per-command output files are untouched.

`findings_history.json` retains scoped findings across successful runs, with
source attribution, roots, first/last observation times and per-source status:
`confirmed` (observed by a provider in this invocation), `cached` (reused),
`not_confirmed` (absent from a source refreshed this run), `not_checked`, or
`out_of_scope` (its root was removed). Cached exports do not advance observation
dates. Legacy checkpoints without dates import with null observation times.
Failed/interrupted runs leave the previous history intact; successfully saved
checkpoints can contribute their original observation dates after resuming.
Historical names are not automatically put back into current scan targets.
This upgrade changes active commands, so previous active checkpoints are
recollected once; unchanged passive checkpoints remain reusable.

The built-in commands use `-n bbot_active` / `-n bbot_passive` and their matching copy
paths. PureDNS retains its three top-level output files; a following explicit
`cp` copies its discovered domains to `subdomains/subdomains_puredns.txt`
before domain-list preparation. This includes PureDNS findings in the existing
`subdomains/subdomains_*.txt` collection commands. The command text, tool options and action order are kept in the standalone
script; Markdown documentation does not influence a run.
Local tests and default repository-root output files are ignored by Git.

## To Do

- [x] **Create Wildcard Hunter Script**  
  Develop a script to search for wildcard certificates, streamlining the process of certificate discovery and verification.

- [ ] **Create Privesc Script**  
  Build a script that deploys Linpeas on multiple systems to streamline system auditing and security checks.

- [ ] **OSINT script**
  Develop a script that will automate the entire OSINT process including:
  - [ ] Shodan
  - [ ] Censys
  - [ ] Bbot
  - [ ] Puredns
  - [ ] Katana
  - [ ] Ffuf - Vhosts
  - [ ] Ffuf/Feroxbuster - Folders
  - [ ] Wildcard
  - [ ] SSL Ciphers
  - [ ] Nmap/Masscan
  - [ ] Nuclei
  - [ ] httpx
  - [ ] Metaforge
  - [ ] Anything else?

- [ ] **Implement Additional Utility Scripts**  
  Explore and integrate further tools and enhancements to expand the functionality of this project.

  
