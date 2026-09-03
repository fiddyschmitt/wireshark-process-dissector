package main

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Orchestrator struct {
	c    *Config
	vbox *VBox
}

func NewOrchestrator(c *Config) *Orchestrator {
	return &Orchestrator{c: c, vbox: NewVBox(c.VBoxManagePath)}
}

func logf(format string, a ...any) { fmt.Printf(format+"\n", a...) }

// prep is idempotent: ensure tools/network, download the image, build the reusable base.vdi.
func (o *Orchestrator) prep() error {
	if !o.vbox.toolExists() {
		return fmt.Errorf("VBoxManage not found at %s", o.c.VBoxManagePath)
	}
	if !o.vbox.bridgeAdapterExists(o.c.Net.BridgeAdapter) {
		return fmt.Errorf("bridge adapter %q not found (VBoxManage list bridgedifs)", o.c.Net.BridgeAdapter)
	}
	if err := os.MkdirAll(o.c.WorkingDir, 0o755); err != nil {
		return err
	}

	if err := o.downloadImageIfMissing(); err != nil {
		return err
	}

	if _, err := os.Stat(o.c.BaseVdiPath()); err == nil {
		logf("base.vdi: present")
	} else {
		logf("base.vdi: converting from qcow2 (one-time)...")
		if err := o.vbox.cloneMediumToVdi(o.c.ImagePath(), o.c.BaseVdiPath()); err != nil {
			return err
		}
		o.vbox.tryCloseDisk(o.c.ImagePath())
		logf("base.vdi: created")
	}
	return nil
}

func (o *Orchestrator) downloadImageIfMissing() error {
	path := o.c.ImagePath()
	if fi, err := os.Stat(path); err == nil && fi.Size() > 0 {
		if o.c.Image.Sha512 != "" {
			logf("image: present, verifying checksum...")
			ok, err := verifySha512(path, o.c.Image.Sha512)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("image checksum mismatch (delete %s to re-download)", path)
			}
			logf("image: checksum OK")
		} else {
			logf("image: present")
		}
		return nil
	}

	logf("image: downloading %s", o.c.Image.URL)
	tmp := path + ".part"
	// A stalled mirror must not hang prep forever; the image is ~450 MB so allow a long overall cap.
	client := &http.Client{Timeout: 2 * time.Hour}
	resp, err := client.Get(o.c.Image.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	total := resp.ContentLength
	pw := &progressWriter{total: total, start: time.Now()}
	_, err = io.Copy(io.MultiWriter(f, pw), resp.Body)
	f.Close()
	fmt.Println()
	if err != nil {
		os.Remove(tmp) // never leave a truncated .part behind
		return err
	}

	if o.c.Image.Sha512 != "" {
		logf("image: verifying checksum...")
		ok, err := verifySha512(tmp, o.c.Image.Sha512)
		if err != nil {
			return err
		}
		if !ok {
			os.Remove(tmp)
			return fmt.Errorf("image checksum mismatch after download")
		}
	}
	return os.Rename(tmp, path)
}

// create builds the seed ISO and the VM (persistent, resized disk + seed ISO). Idempotent:
// an existing VM is left untouched (its seed ISO may be held open by VirtualBox while it
// runs, and the seed only matters on first boot — use 'deploy' to push newer sources), and a
// failure part-way through VM setup rolls the registration back so the next run starts clean.
func (o *Orchestrator) create() error {
	if err := o.prep(); err != nil {
		return err
	}

	if o.vbox.vmExists(o.c.VM.Name) {
		logf("VM %q: already registered", o.c.VM.Name)
		return nil
	}

	logf("seed ISO: building (embeds current dissector + tests)...")
	if err := buildSeedIso(o.c, o.c.SeedIsoPath()); err != nil {
		return err
	}

	logf("disk: cloning base.vdi -> %s and resizing to %d MB...", o.c.VM.Name+".vdi", o.c.VM.DiskMB)
	if _, err := os.Stat(o.c.DiskPath()); err != nil {
		if err := o.vbox.cloneVdi(o.c.BaseVdiPath(), o.c.DiskPath()); err != nil {
			return err
		}
		if err := o.vbox.resizeVdi(o.c.DiskPath(), o.c.VM.DiskMB); err != nil {
			return err
		}
	}

	logf("VM %q: creating...", o.c.VM.Name)
	if err := o.vbox.createVM(o.c.VM.Name); err != nil {
		return err
	}
	if err := o.configureAndAttach(); err != nil {
		logf("VM %q: setup failed (%v) — rolling back the registration", o.c.VM.Name, err)
		o.vbox.unregister(o.c.VM.Name)
		return err
	}
	logf("VM %q: created (%d MB RAM, %d CPUs, %d MB disk, bridged %s, static %s)",
		o.c.VM.Name, o.c.VM.MemoryMB, o.c.VM.CPUs, o.c.VM.DiskMB, o.c.Net.BridgeAdapter, o.c.Net.IP)
	return nil
}

// configureAndAttach applies the VM settings and attaches the disk + seed ISO to a freshly
// registered VM. Kept separate so create() can roll back on any failure.
func (o *Orchestrator) configureAndAttach() error {
	if err := o.vbox.configureVM(o.c); err != nil {
		return err
	}
	if err := o.vbox.ensureSataController(o.c.VM.Name); err != nil {
		return err
	}
	if err := o.vbox.attachDisk(o.c.VM.Name, o.c.DiskPath()); err != nil {
		return err
	}
	if err := o.vbox.attachSeedIso(o.c.VM.Name, o.c.SeedIsoPath()); err != nil {
		return err
	}
	if ga := o.c.GuestAdditionsIso; ga != "" {
		if _, err := os.Stat(ga); err == nil {
			if err := o.vbox.attachGuestAdditionsIso(o.c.VM.Name, ga); err != nil {
				return err
			}
			logf("guest additions ISO attached (%s)", ga)
		} else {
			logf("guest additions ISO not found at %s — skipping (desktop will run at a fixed resolution)", ga)
		}
	}
	return nil
}

// up creates the VM if needed, starts it (GUI by default for manual Wireshark use), then waits
// for SSH and the provisioning marker.
func (o *Orchestrator) up(gui bool) error {
	if err := o.create(); err != nil {
		return err
	}
	if o.vbox.vmRunning(o.c.VM.Name) {
		logf("VM %q: already running", o.c.VM.Name)
	} else {
		mode := "GUI window"
		if !gui {
			mode = "headless"
		}
		logf("VM %q: starting (%s)...", o.c.VM.Name, mode)
		if err := o.vbox.startVM(o.c.VM.Name, gui); err != nil {
			return err
		}
	}

	logf("waiting for SSH at %s (first boot expands the disk + boots the desktop)...", o.c.Net.IP)
	if err := waitForSSH(o.c, time.Duration(o.c.VM.SSHReadyTimeoutSeconds)*time.Second, logf1); err != nil {
		return err
	}
	logf("SSH up. waiting for provisioning to finish (installs desktop + Wireshark)...")
	if err := waitForProvisioned(o.c, time.Duration(o.c.VM.ProvisionTimeoutSeconds)*time.Second, logf1); err != nil {
		return err
	}
	logf("provisioning complete — desktop is up, dissector installed.")
	return nil
}

// test runs the dissector self-tests, then a short live capture, over SSH.
func (o *Orchestrator) test() error {
	if !o.vbox.vmRunning(o.c.VM.Name) {
		return fmt.Errorf("VM %q is not running (run 'up' first)", o.c.VM.Name)
	}
	if err := waitForSSH(o.c, 30*time.Second, logf1); err != nil {
		return err
	}

	logf("== self-tests (tshark + run_tests.lua) ==")
	out, errb, sshErr := runSSH(o.c, "cd ~/dissector && tshark -X lua_script:tests/run_tests.lua -r tests/empty.pcap 2>&1 | tail -25")
	if sshErr != nil {
		return fmt.Errorf("self-tests: ssh failed: %v %s", sshErr, strings.TrimSpace(errb))
	}
	fmt.Println(strings.TrimSpace(out + errb))
	if !strings.Contains(out+errb, "FAIL 0") {
		return fmt.Errorf("self-tests did not report FAIL 0")
	}

	logf("")
	logf("== live capture (Linux /proc resolver) ==")
	iface, _, ifErr := runSSH(o.c, "ip -o -4 route show to default | awk '{print $5; exit}'")
	iface = strings.TrimSpace(iface)
	if ifErr != nil || iface == "" {
		logf("(could not determine the default interface%s; assuming enp0s3)", errSuffix(ifErr))
		iface = "enp0s3"
	}
	// Generate our own traffic while capturing on the primary interface; check the dissector
	// resolves this VM's outbound connections to a process with a path. A rate-limited download
	// keeps the socket alive across several /proc scans (short-lived connections can be missed),
	// with a burst of quick requests alongside it.
	cmd := fmt.Sprintf(
		"cd ~/dissector && "+
			"( curl -s --limit-rate 300k --max-time 12 -o /dev/null https://deb.debian.org/debian/dists/trixie/main/Contents-amd64.gz 2>/dev/null & ) ; "+
			"( for i in 1 2 3 4 5 6 7 8 9; do curl -s -o /dev/null https://example.com; sleep 1; done & ) ; sleep 2 ; "+
			"tshark -Q -X lua_script:process_dissector.lua -i %s -f 'tcp port 443' -a duration:9 "+
			"-T fields -E separator='|' -e ip.src -e tcp.srcport -e process.side -e process.pid -e process.name -e process.path 2>/dev/null "+
			"| awk -F'|' '$5!=\"\"' | sort -u | head -8",
		iface)
	out, errb, sshErr = runSSH(o.c, cmd)
	if sshErr != nil {
		return fmt.Errorf("live capture: ssh failed: %v %s", sshErr, strings.TrimSpace(errb))
	}
	res := strings.TrimSpace(out + errb)
	fmt.Println(res)
	if res == "" {
		logf("(no process-resolved packets captured this run — short-lived connections can be missed; retry, or verify in the GUI)")
	} else {
		logf("live capture resolved packets to a process ✓")
	}
	return nil
}

// deploy rebuilds the bundle from local sources and pushes it to a running VM (update without recreate).
func (o *Orchestrator) deploy() error {
	if err := waitForSSH(o.c, 20*time.Second, logf1); err != nil {
		return fmt.Errorf("VM not reachable over SSH: %w", err)
	}
	logf("building bundle from %s ...", o.c.resolveDissectorDir())
	bundle, err := buildBundle(o.c.resolveDissectorDir())
	if err != nil {
		return err
	}
	logf("uploading (%d KB) ...", len(bundle)/1024)
	if err := uploadFile(o.c, bundle, "/tmp/dissector-bundle.tgz"); err != nil {
		return err
	}
	script := "set -e; rm -rf ~/dissector && mkdir -p ~/dissector && tar xzf /tmp/dissector-bundle.tgz -C ~/dissector; " +
		"mkdir -p ~/.local/lib/wireshark/plugins ~/.config/wireshark; " +
		"cp ~/dissector/process_dissector.lua ~/.local/lib/wireshark/plugins/process_dissector.lua; " +
		"[ -f ~/dissector/preferences ] && cp ~/dissector/preferences ~/.config/wireshark/preferences; " +
		"echo deployed"
	out, errb, runErr := runSSH(o.c, script)
	if runErr != nil {
		return fmt.Errorf("%v: %s", runErr, strings.TrimSpace(out+errb))
	}
	logf("deployed. (In a running Wireshark, use Analyze > Reload Lua Plugins to pick it up.)")
	return nil
}

func (o *Orchestrator) down() error {
	if !o.vbox.vmExists(o.c.VM.Name) {
		return fmt.Errorf("VM %q not registered", o.c.VM.Name)
	}
	if !o.vbox.vmRunning(o.c.VM.Name) {
		logf("VM %q: already off", o.c.VM.Name)
		return nil
	}
	logf("VM %q: requesting graceful shutdown...", o.c.VM.Name)
	o.vbox.acpiPowerButton(o.c.VM.Name)
	if o.vbox.waitUntilOff(o.c.VM.Name, time.Duration(o.c.VM.ShutdownTimeoutSeconds)*time.Second) {
		logf("VM %q: off", o.c.VM.Name)
		return nil
	}
	logf("VM %q: forcing power off", o.c.VM.Name)
	return o.vbox.powerOff(o.c.VM.Name)
}

func (o *Orchestrator) destroy() error {
	if o.vbox.vmExists(o.c.VM.Name) {
		logf("VM %q: unregistering + deleting...", o.c.VM.Name)
		o.vbox.unregister(o.c.VM.Name)
	}
	// clonemedium leaves the disk registered; unregister --delete removes attached disks, but the
	// standalone seed ISO and any orphaned disk file are cleaned here.
	for _, p := range []string{o.c.SeedIsoPath(), o.c.DiskPath()} {
		if _, err := os.Stat(p); err == nil {
			o.vbox.tryCloseDisk(p)
			if err := os.Remove(p); err == nil {
				logf("removed %s", p)
			}
		}
	}
	logf("destroyed. (base.vdi and the downloaded image are kept for fast re-create.)")
	return nil
}

func (o *Orchestrator) status() error {
	fmt.Printf("VM name       : %s\n", o.c.VM.Name)
	fmt.Printf("registered    : %v\n", o.vbox.vmExists(o.c.VM.Name))
	fmt.Printf("state         : %s\n", o.vbox.vmState(o.c.VM.Name))
	fmt.Printf("IP (static)   : %s\n", o.c.Net.IP)
	if o.vbox.vmRunning(o.c.VM.Name) {
		if err := waitForSSH(o.c, 4*time.Second, nil); err == nil {
			out, _, rerr := runSSH(o.c, "{ test -f /run/dissector-setup-complete || test -f /var/lib/dissector/setup-complete; } && echo yes || echo no")
			fmt.Printf("ssh           : up\n")
			if rerr != nil {
				fmt.Printf("provisioned   : unknown (ssh error: %v)\n", rerr)
			} else {
				fmt.Printf("provisioned   : %s\n", strings.TrimSpace(out))
			}
		} else {
			fmt.Printf("ssh           : not ready\n")
		}
	}
	fmt.Printf("manual login  : ssh %s@%s   (password: see config, default 'live')\n", o.c.VM.Username, o.c.Net.IP)
	return nil
}

// errSuffix formats an optional error for inline log messages.
func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	return ": " + err.Error()
}

func logf1(s string) { fmt.Println(s) }

func verifySha512(path, expected string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == strings.ToLower(strings.TrimSpace(expected)), nil
}

type progressWriter struct {
	total   int64
	written int64
	start   time.Time
	lastMs  int64
}

func (p *progressWriter) Write(b []byte) (int, error) {
	n := len(b)
	p.written += int64(n)
	ms := time.Since(p.start).Milliseconds()
	if ms-p.lastMs >= 500 {
		p.lastMs = ms
		mb := float64(p.written) / (1024 * 1024)
		spd := mb / (float64(ms) / 1000.0)
		if p.total > 0 {
			fmt.Printf("\r  %.0f%% (%.1f/%.1f MB, %.1f MB/s)   ",
				float64(p.written)*100/float64(p.total), mb, float64(p.total)/(1024*1024), spd)
		} else {
			fmt.Printf("\r  %.1f MB (%.1f MB/s)   ", mb, spd)
		}
	}
	return n, nil
}
