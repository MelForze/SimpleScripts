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

Both collectors accept `--user-agent` (or `-ua`) and `--dry-run`:

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

  
