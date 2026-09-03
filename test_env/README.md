# dissector-test-env

An on-demand **Linux desktop VM** for the Process Info dissector. It stands up a Debian 13 VM
in VirtualBox with an XFCE desktop, Wireshark, and the dissector pre-installed, so you can:

- **run the dissector's self-tests** under real Linux Wireshark + Lua (over SSH), and
- **verify capture by hand** in the Wireshark GUI (the VM boots straight to a desktop).

It is the Go counterpart of `file_tunnel/ft_test_env`: same approach (drive VirtualBox with
`VBoxManage`, provision with a cloud-init **NoCloud** seed ISO), trimmed to one GUI node and
written in Go.

## How it works

1. **Template** — download the Debian "generic" cloud qcow2 (checksummed) and convert it once to
   a reusable `base.vdi` (`VBoxManage clonemedium`).
2. **Per-VM disk** — clone `base.vdi` to `<vm>.vdi` and resize it to 30 GB. It's a *persistent*
   disk (unlike ft's immutable root): a desktop won't fit a tiny reset-on-boot root, and you want
   your manual state to survive reboots. cloud-init's `growpart` expands the guest root to fill it.
3. **Seed** — build a `cidata` ISO (`meta-data` + `user-data` + `network-config`) carrying a
   static IP, the `user` account (password + your SSH key + NOPASSWD sudo), an embedded
   provisioning script, and a tarball of the current dissector + tests.
4. **Boot + provision** — create/configure the VM (bridged NIC, VMSVGA video), start it in a
   **GUI window**, wait for SSH, then wait for the setup script to finish (it installs XFCE +
   LightDM autologin + Wireshark, wires up non-root capture, and drops the dissector plugin +
   column preferences into place). Completion is signalled by `/run/dissector-setup-complete`.

The guest uses the dissector's **pure-`/proc` resolver** (Debian's kernel is ≥ 5.14), so no
background helper is needed on Linux — a good complement to the Windows/macOS helper path.

**Guest Additions.** Debian 13's repositories carry no `virtualbox-guest-*` packages, so the
tool attaches the host's `VBoxGuestAdditions.iso` (from the VirtualBox install folder) as a
second DVD and the provisioning script installs it from there (kernel headers + dkms + the
`VBoxLinuxAdditions.run` installer). This gives version-matched additions: dynamic resolution,
shared clipboard and mouse integration. It is best-effort — if the ISO is missing the desktop
still works, at a fixed resolution. Override the path with `guestAdditionsIso` in `config.json`.

## Prerequisites

- VirtualBox (`VBoxManage.exe`) and Go, both already on this machine.
- A bridged host NIC on the LAN (default: the I211, same as ft) and a free static IP
  (default `192.168.0.66`).

## Build

```
cd test_env
go build -o dissector-test-env.exe .
```

## Use

```
dissector-test-env up        # create + start (GUI) + provision; leaves a usable desktop
dissector-test-env test      # run the self-tests + a short live capture over SSH
dissector-test-env deploy    # push the current local dissector to the running VM
dissector-test-env status    # state / IP / SSH / provisioned
dissector-test-env down      # graceful power off
dissector-test-env destroy   # delete the VM + its disk + seed (keeps base image)
```

Typical flow: **`up` → `test` → verify by hand in the GUI → `down`** (or `destroy`).

### Verifying by hand

The VM auto-logs into XFCE. In the VirtualBox window: launch **Wireshark** (desktop icon),
start a capture on the wired interface, and use the **Generate Traffic** desktop icon (or a
browser / `curl` in a terminal). Packets get **PID, Process, Side, Exe file, Exe folder**
columns. Because Linux resolution reads `/proc`, your own processes (the browser, curl) resolve
without root; system daemons need root (`sudo wireshark` if you want those too).

### Updating the dissector without rebuilding the VM

Edit `../process_dissector.lua` (or the tests), then `dissector-test-env deploy`. In a running
Wireshark, **Analyze → Reload Lua Plugins** picks up the change.

## Configuration

Defaults live in `config.go`. To override, drop a `config.json` next to the exe (or pass
`-config <file>`), e.g.:

```json
{ "net": { "ip": "192.168.0.67", "bridgeAdapter": "Intel(R) I211 Gigabit Network Connection" },
  "vm":  { "name": "dissector-desktop", "memoryMb": 4096, "cpus": 3, "diskMb": 30720 } }
```

## Files

| File | Role |
|------|------|
| `main.go` | CLI |
| `config.go` | config + defaults |
| `vbox.go` | `VBoxManage` wrapper |
| `bundle.go` | packs the dissector + tests + column prefs into a tarball |
| `seed.go` | cloud-init NoCloud seed ISO (uses `kdomanski/iso9660`) |
| `setup_linux.sh` | guest provisioning (embedded, run by cloud-init) |
| `ssh.go` | SSH wait / run / upload (`golang.org/x/crypto/ssh`) |
| `orchestrator.go` | create / up / test / deploy / down / destroy / status |
