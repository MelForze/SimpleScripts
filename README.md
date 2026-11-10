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

On a terminal, FFuFScan displays a dashboard with host queues, selected-origin
details, progress and recent events. Use `--ui plain` for the previous text view
or `--ui dashboard` to require the full-screen view. Arrow keys select a host;
`p` + Enter pauses/resumes new jobs and recursive passes, `l` + Enter toggles its
stderr log, and `s` + Enter stops the selected host and its queued origins.
`s <id|host>` + Enter still targets a specific job or host. Already-running ffuf
passes continue during a queue pause. Redirected output uses plain logs.

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

  
