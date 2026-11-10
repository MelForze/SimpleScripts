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
installations; `--templates` has been removed. The only intentional command
change is that the DNSDumpster header reads its key from the environment instead
of embedding a literal key from Markdown.

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

Results default to the current launch directory; `-o` selects another result
directory. The default is `--mode all`: passive collection first, then active collection.
`--mode passive` and `--mode active` select one part. Domain-list command variants
are used even for a single domain. Each root gets an isolated workspace with its
own `top_domains.txt`; stages run source first across the roots, preserving the
action order. The collector creates the `subdomains/` directory and copies
`~/selflists/dns/resolvers.txt` into active workspaces as `resolvers.txt`. Other paths
and tool options retain their agreed values.

Passive order: DNSDumpster → manual Subdomainfinder/Pentest-tool/Nmapper/SuIP
entries (no commands supplied) → crt.sh → Subfinder → Findomain → Assetfinder →
Docker BBOT → copy BBOT results. Active order: Docker BBOT → copy → PureDNS →
copy PureDNS findings into `subdomains/` → prepare domain list → DNS records → SRV → extract hosts → IPv4-based PTR via
`dnsx` → collect findings → prepare/run/collect AXFR → final domains →
`host -t A` → unique IPv4 addresses. The single-domain, standalone-IP and
`nets.txt` alternatives are not run in addition to the chosen list variants.
Company research, leaks, code and job-site sections are outside this version.

There are no collector-added rates, request retries, timeouts, host limits or
UA overrides. In particular, `dnsx -rl 100`, the API-loop `sleep 2`, BBOT's
`--platform linux/amd64 --rm -it --pull=always`, and PureDNS's wordlist path come
from the agreed commands. AXFR is executed at its established position.
BBOT requires an interactive terminal because its command retains `-it`.
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
- Active collection uses `~/selflists/dns/biggest_dnslist.txt` and
  `~/selflists/dns/resolvers.txt`. The help lists these required paths too.

Use the same output directory when adding root domains. Completed stages are
checked against output hashes and reused; new roots are collected separately.
An interrupted/failed command is retried in a clean workspace with copies of
verified earlier-stage outputs. Use `--refresh` after changing tool configs or
keys, or to repeat collection. There is one writer per project. New checkpoints
are in `.osint/template-state.json`; legacy `template-state.json` checkpoints
are read if the new state file is absent. The earlier collector's `state.sqlite3` is not
reused because its commands differed. Old data is not deleted.

`--dry-run` prints a read-only plan without running tools or creating/modifying
project files. API keys are redacted in progress/plans; the actual command is
executed with environment-variable expansion by Bash. Live tool output goes to the terminal, preserving BBOT's
interactive operation. A nonzero shell exit or a missing expected output stops
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

  
