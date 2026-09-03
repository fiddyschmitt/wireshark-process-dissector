package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// VBox is a thin wrapper over VBoxManage.exe: methods shell out and parse text output,
// mirroring ft_test_env's VBoxManager.
type VBox struct {
	path string
}

func NewVBox(path string) *VBox { return &VBox{path: path} }

type procResult struct {
	code   int
	stdout string
	stderr string
}

func (p procResult) ok() bool       { return p.code == 0 }
func (p procResult) combined() string {
	return strings.TrimSpace(p.stdout + "\n" + p.stderr)
}

func (v *VBox) tryRun(args ...string) procResult {
	cmd := exec.Command(v.path, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			code = -1
			errb.WriteString(err.Error())
		}
	}
	return procResult{code: code, stdout: out.String(), stderr: errb.String()}
}

// run executes VBoxManage and returns an error if it exits non-zero.
func (v *VBox) run(args ...string) (string, error) {
	r := v.tryRun(args...)
	if !r.ok() {
		return "", fmt.Errorf("VBoxManage %s: %s", strings.Join(args, " "), r.combined())
	}
	return r.stdout, nil
}

func (v *VBox) toolExists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

// ---- queries ----

func (v *VBox) vmExists(name string) bool {
	return strings.Contains(v.tryRun("list", "vms").stdout, `"`+name+`"`)
}

func (v *VBox) vmRunning(name string) bool {
	return strings.Contains(v.tryRun("list", "runningvms").stdout, `"`+name+`"`)
}

// vmState returns "running"/"poweroff"/"saved"/... or "unknown". Use this (not vmRunning) when
// you need the VM FULLY off (lock released) — a VM leaves the running list before that completes.
func (v *VBox) vmState(name string) string {
	r := v.tryRun("showvminfo", name, "--machinereadable")
	if !r.ok() {
		return "unknown"
	}
	for _, line := range strings.Split(r.stdout, "\n") {
		if strings.HasPrefix(line, "VMState=") {
			return strings.Trim(strings.TrimPrefix(line, "VMState="), "\"\r ")
		}
	}
	return "unknown"
}

func (v *VBox) bridgeAdapterExists(name string) bool {
	for _, line := range strings.Split(v.tryRun("list", "bridgedifs").stdout, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Name:") {
			got := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "Name:"))
			if strings.EqualFold(got, name) {
				return true
			}
		}
	}
	return false
}

func (v *VBox) mediumRegistered(path string) bool {
	return strings.Contains(strings.ToLower(v.tryRun("list", "hdds").stdout), strings.ToLower(path))
}

// ---- disk template ----

// cloneMediumToVdi converts the downloaded qcow2 into a VDI (the reusable base template).
func (v *VBox) cloneMediumToVdi(srcQcow2, destVdi string) error {
	_, err := v.run("clonemedium", "disk", srcQcow2, destVdi, "--format", "VDI")
	return err
}

func (v *VBox) tryCloseDisk(path string) { v.tryRun("closemedium", "disk", path) }

// cloneVdi makes a fresh, independent persistent copy of the base VDI for a VM.
func (v *VBox) cloneVdi(srcVdi, destVdi string) error {
	_, err := v.run("clonemedium", "disk", srcVdi, destVdi, "--format", "VDI")
	return err
}

// resizeVdi grows a VDI's virtual size (MB); cloud-init growpart expands the guest root to fill it.
func (v *VBox) resizeVdi(vdiPath string, sizeMB int) error {
	_, err := v.run("modifymedium", "disk", vdiPath, "--resize", fmt.Sprint(sizeMB))
	return err
}

// ---- VM lifecycle ----

func (v *VBox) createVM(name string) error {
	_, err := v.run("createvm", "--name", name, "--ostype", "Debian_64", "--register")
	return err
}

// configureVM sets memory/cpu/network/video for a desktop guest shown in the VBox GUI window.
func (v *VBox) configureVM(c *Config) error {
	_, err := v.run("modifyvm", c.VM.Name,
		"--memory", fmt.Sprint(c.VM.MemoryMB),
		"--cpus", fmt.Sprint(c.VM.CPUs),
		"--ioapic", "on",
		"--rtcuseutc", "on",
		"--nic1", "bridged",
		"--bridgeadapter1", c.Net.BridgeAdapter,
		"--graphicscontroller", "vmsvga",
		"--vram", fmt.Sprint(c.VM.VRAMMB),
		"--accelerate3d", "off",
		"--audio-driver", "none",
		"--boot1", "disk",
		"--boot2", "dvd",
		"--clipboard-mode", "bidirectional")
	return err
}

func (v *VBox) ensureSataController(name string) error {
	// port 0 = root disk, port 1 = cloud-init seed ISO, port 2 = Guest Additions ISO (optional)
	r := v.tryRun("storagectl", name, "--name", "SATA", "--add", "sata",
		"--controller", "IntelAhci", "--portcount", "3")
	if !r.ok() && !strings.Contains(strings.ToLower(r.combined()), "already exists") {
		return fmt.Errorf("%s", r.combined())
	}
	return nil
}

func (v *VBox) attachDisk(name, vdiPath string) error {
	_, err := v.run("storageattach", name, "--storagectl", "SATA", "--port", "0", "--device", "0",
		"--type", "hdd", "--medium", vdiPath)
	return err
}

func (v *VBox) attachSeedIso(name, isoPath string) error {
	_, err := v.run("storageattach", name, "--storagectl", "SATA", "--port", "1", "--device", "0",
		"--type", "dvddrive", "--medium", isoPath)
	return err
}

// attachGuestAdditionsIso attaches the host's VBoxGuestAdditions.iso on SATA port 2 so the
// guest's provisioning can install version-matched Guest Additions.
func (v *VBox) attachGuestAdditionsIso(name, isoPath string) error {
	_, err := v.run("storageattach", name, "--storagectl", "SATA", "--port", "2", "--device", "0",
		"--type", "dvddrive", "--medium", isoPath)
	return err
}

// startVM boots the VM. gui=true opens a VirtualBox window (for manual Wireshark use);
// gui=false runs headless.
func (v *VBox) startVM(name string, gui bool) error {
	kind := "gui"
	if !gui {
		kind = "headless"
	}
	_, err := v.run("startvm", name, "--type", kind)
	return err
}

func (v *VBox) powerOff(name string) error {
	_, err := v.run("controlvm", name, "poweroff")
	return err
}

// acpiPowerButton requests a graceful guest shutdown.
func (v *VBox) acpiPowerButton(name string) { v.tryRun("controlvm", name, "acpipowerbutton") }

func (v *VBox) waitUntilOff(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if v.vmState(name) == "poweroff" {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// unregister powers off (best effort) then removes the VM and its files.
func (v *VBox) unregister(name string) {
	if v.vmRunning(name) {
		v.tryRun("controlvm", name, "poweroff")
		v.waitUntilOff(name, 30*time.Second)
	}
	v.tryRun("unregistervm", name, "--delete")
}
