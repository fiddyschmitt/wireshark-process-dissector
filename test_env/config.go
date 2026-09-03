package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config is the strongly-typed configuration for the dissector test-VM orchestrator.
// Defaults below stand up a single Debian desktop VM on the LAN; override via config.json
// (written next to the executable / working dir) or the -config flag.
type Config struct {
	VBoxManagePath string `json:"vboxManagePath"`
	WorkingDir     string `json:"workingDir"` // holds the image, base.vdi, per-VM disk and seed ISO

	Image ImageConfig `json:"image"`
	Net   NetConfig   `json:"net"`
	VM    VMConfig    `json:"vm"`

	// Where the dissector sources live (process_dissector.lua + tests/). Default: the parent
	// directory of this tool, i.e. the process_dissector project. Read fresh at seed/deploy time.
	DissectorDir string `json:"dissectorDir"`

	// The host's VirtualBox Guest Additions ISO. Attached as a second DVD so the guest can install
	// version-matched additions (dynamic resolution, clipboard, mouse integration) — Debian 13's
	// repos do not carry virtualbox-guest-* packages. Skipped if the file is missing.
	GuestAdditionsIso string `json:"guestAdditionsIso"`
}

type ImageConfig struct {
	URL      string `json:"url"`
	Sha512   string `json:"sha512"`
	FileName string `json:"fileName"`
}

type NetConfig struct {
	BridgeAdapter string `json:"bridgeAdapter"`
	IP            string `json:"ip"`
	Gateway       string `json:"gateway"`
	DNS           string `json:"dns"`
	PrefixLength  int    `json:"prefixLength"`
}

type VMConfig struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	Password string `json:"password"`
	MemoryMB int    `json:"memoryMb"`
	CPUs     int    `json:"cpus"`
	VRAMMB   int    `json:"vramMb"`
	DiskMB   int    `json:"diskMb"`
	SSHPort  int    `json:"sshPort"`

	SSHReadyTimeoutSeconds    int `json:"sshReadyTimeoutSeconds"`
	ProvisionTimeoutSeconds   int `json:"provisionTimeoutSeconds"`
	ShutdownTimeoutSeconds    int `json:"shutdownTimeoutSeconds"`
}

// DefaultConfig returns the built-in defaults (a single Debian 13 XFCE desktop VM on 192.168.0.66).
func DefaultConfig() *Config {
	return &Config{
		VBoxManagePath:    `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`,
		WorkingDir:        `C:\dissector_test_env`,
		GuestAdditionsIso: `C:\Program Files\Oracle\VirtualBox\VBoxGuestAdditions.iso`,
		Image: ImageConfig{
			// Debian 13 "generic" cloud image (broad drivers under VirtualBox; grows root via cloud-init).
			URL:      "https://cloud.debian.org/images/cloud/trixie/20260601-2496/debian-13-generic-amd64-20260601-2496.qcow2",
			Sha512:   "97675b27e69153002c4e13644e36200c8f9067f661dca00918c54f1cacbdb88d4bff8c0fbf5cf5d63a0397bdf0cc472d7a6372bae5281bf7ced756249c10f8a2",
			FileName: "debian-13-generic-amd64-20260601-2496.qcow2",
		},
		Net: NetConfig{
			BridgeAdapter: "Intel(R) I211 Gigabit Network Connection",
			IP:            "192.168.0.66",
			Gateway:       "192.168.0.1",
			DNS:           "8.8.8.8",
			PrefixLength:  24,
		},
		VM: VMConfig{
			Name:                    "dissector-desktop",
			Hostname:                "dissector-vm",
			Username:                "user",
			Password:                "live",
			MemoryMB:                4096,
			CPUs:                    3,
			VRAMMB:                  128,
			DiskMB:                  30720, // 30 GB persistent root (desktop + wireshark + captures)
			SSHPort:                 22,
			SSHReadyTimeoutSeconds:  300,
			ProvisionTimeoutSeconds: 1500, // first boot installs a desktop over apt
			ShutdownTimeoutSeconds:  90,
		},
	}
}

func (c *Config) BaseVdiPath() string { return filepath.Join(c.WorkingDir, "base.vdi") }
func (c *Config) DiskPath() string    { return filepath.Join(c.WorkingDir, c.VM.Name+".vdi") }
func (c *Config) ImagePath() string   { return filepath.Join(c.WorkingDir, c.Image.FileName) }
func (c *Config) SeedIsoPath() string { return filepath.Join(c.WorkingDir, c.VM.Name+"-seed.iso") }

// LoadConfig reads config.json if present, layering it over the defaults; missing file = defaults.
func LoadConfig(path string) (*Config, error) {
	c := DefaultConfig()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	return c, nil
}

// resolveDissectorDir returns the dissector source dir: the configured one, else the first of
// (parent of the exe's folder, parent of the working dir, working dir) that actually contains
// process_dissector.lua. The exe-based guess is right for the built binary in test_env/ but
// meaningless under `go run` (a temp dir), hence the fallbacks.
func (c *Config) resolveDissectorDir() string {
	if c.DissectorDir != "" {
		return c.DissectorDir
	}
	var candidates []string
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(filepath.Dir(exe)))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Dir(wd), wd)
	}
	for _, dir := range candidates {
		if _, err := os.Stat(filepath.Join(dir, "process_dissector.lua")); err == nil {
			return dir
		}
	}
	return ".."
}
