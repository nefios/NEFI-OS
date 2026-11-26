<p align="center">
  <img src="branding/installer/logo.png" alt="NEFI OS logo" width="220">
</p>

<h1 align="center">NEFI OS</h1>

<p align="center">
  <b>Network Event Forensics Intelligence</b><br>
  A Debian 13 Linux distribution for defensive security (Blue Team).<br>
  Hardening, monitoring, forensics and incident response from a single desktop application.
</p>

<p align="center">
  <a href="https://github.com/nefios/NEFI-OS/releases"><img src="https://img.shields.io/github/v/release/nefios/NEFI-OS" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/nefios/NEFI-OS" alt="License: GPL v3"></a>
  <a href="https://nefi-os.gitbook.io/docs/project/support/known-limitations"><img src="https://img.shields.io/badge/status-pre--release-orange" alt="Status: pre-release"></a>
  <a href="https://www.debian.org/"><img src="https://img.shields.io/badge/base-Debian%2013-A81D33" alt="Base: Debian 13"></a>
  <a href="https://nefi-os.gitbook.io/docs"><img src="https://img.shields.io/badge/docs-GitBook-7AB51D" alt="Documentation"></a>
</p>

<p align="center">
  📖<a href="https://nefi-os.gitbook.io/docs"><b>Read the documentation</b></a>
  &nbsp;·&nbsp;
  ⬇️<a href="https://github.com/nefios/NEFI-OS/releases"><b>Download</b></a>
  &nbsp;·&nbsp;
  🤝<a href="https://nefi-os.gitbook.io/docs/project/development/contributing"><b>Contribute</b></a>
</p>

---

## What is NEFI OS

NEFI OS is plain Debian 13 with KDE Plasma 6 (default), GNOME or Xfce, a hardened baseline applied at installation, and the **NEFI Security Center** on top. It is built for system administrators, small security teams and analysts who want a defensive workstation without assembling and maintaining the toolchain themselves.

- **Measure:** a Security Score from 61 checks, each backed by evidence from the running system, with the points gained by fixing each one.
- **Prevent:** hardening profiles, kernel and SSH assessment with one-click fixes, vulnerability management, attack surface view, Zero Trust mode, USB Guardian, privacy controls, application sandboxing.
- **Detect:** a detection engine with Sigma rules mapped to MITRE ATT&CK, integrity and persistence baseline, threat hunting, Suricata network IDS, Falco runtime alerts, threat intelligence feeds, Lynis audits, honeypots.
- **Investigate:** evidence with chain of custody, memory, disk and timeline forensics, packet capture, file integrity monitoring with AIDE, log viewer.
- **Respond:** incidents, playbooks, host isolation, containment and recovery checklists, CrowdSec automatic blocking.
- **Ask:** NEFI Guardian, a local AI assistant that works offline.

NEFI OS ships no offensive or exploitation tools.

> **Pre-release (0.4).** Validated only in virtual machines. Not recommended for production use or for systems holding critical data. See [Known limitations](https://nefi-os.gitbook.io/docs/project/support/known-limitations).

## Quick start

1. **Download** all the files of the latest release from [Releases](https://github.com/nefios/NEFI-OS/releases) and join the ISO parts:

   ```bash
   cat nefi-os-0.4-amd64.iso.part* > nefi-os-0.4-amd64.iso
   ```

2. **Verify** the ISO. Do not skip this step:

   ```bash
   gpg --import NEFI-OS-RELEASE-KEY.asc
   gpg --verify SHA256SUMS.asc SHA256SUMS
   sha256sum -c SHA256SUMS --ignore-missing
   ```

   The release key fingerprint must be:

   ```
   0CC0 887C BCC8 ED05 E308  FBBA ECF8 8C1D 9133 66D3
   ```

3. **Install** it, preferably in a virtual machine first: follow the [installation guide](https://nefi-os.gitbook.io/docs/start/getting-started/installation).

Windows instructions and full details: [Download and verify](https://nefi-os.gitbook.io/docs/start/getting-started/download-and-verify).

## Documentation

All the documentation is at **[nefi-os.gitbook.io/docs](https://nefi-os.gitbook.io/docs)**.

| Topic | Pages |
|---|---|
| Getting started | [System requirements](https://nefi-os.gitbook.io/docs/start/getting-started/system-requirements) · [Try it in a VM](https://nefi-os.gitbook.io/docs/start/getting-started/try-it-in-a-virtual-machine) · [Installation](https://nefi-os.gitbook.io/docs/start/getting-started/installation) · [First boot](https://nefi-os.gitbook.io/docs/start/getting-started/first-boot) |
| User guide | [NEFI Security Center](https://nefi-os.gitbook.io/docs/user-guide/nefi-security-center) · [NEFI Guardian](https://nefi-os.gitbook.io/docs/user-guide/nefi-security-center/nefi-guardian) |
| Security | [Security by default](https://nefi-os.gitbook.io/docs/user-guide/security/security-by-default) · [Hardening profiles](https://nefi-os.gitbook.io/docs/user-guide/security/hardening-profiles) · [Security Score](https://nefi-os.gitbook.io/docs/user-guide/security/security-score) · [Architecture](https://nefi-os.gitbook.io/docs/user-guide/security/architecture-and-privilege-model) |
| Development | [Build from source](https://nefi-os.gitbook.io/docs/project/development/build-from-source) · [Repository layout](https://nefi-os.gitbook.io/docs/project/development/repository-layout) · [Packages](https://nefi-os.gitbook.io/docs/project/development/packages) |
| Releases | [Release notes 0.4](https://nefi-os.gitbook.io/docs/project/releases/release-notes-0.4) · [Changelog](CHANGELOG.md) · [Signing keys](https://nefi-os.gitbook.io/docs/project/releases/signing-keys) |
| Help | [Troubleshooting](https://nefi-os.gitbook.io/docs/project/support/troubleshooting) · [Known limitations](https://nefi-os.gitbook.io/docs/project/support/known-limitations) |

## Contributing

Bug reports, test results and pull requests are welcome. Reports from hypervisors and physical hardware are especially useful, because NEFI OS has been validated only in virtual machines.

Read the [contributing guide](https://nefi-os.gitbook.io/docs/project/development/contributing) before opening a pull request.

## Security

**Do not report vulnerabilities in public issues.** Use GitHub's private reporting: **Security** tab → **Report a vulnerability**. See [SECURITY.md](SECURITY.md).

## License

NEFI OS is released under the [GNU General Public License v3.0](LICENSE). Debian packages, Ollama and other third-party components keep their own licenses.
