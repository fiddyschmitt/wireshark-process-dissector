package main

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kdomanski/iso9660"
)

//go:embed setup_linux.sh
var setupScript []byte

// buildSeedIso writes the cloud-init NoCloud "cidata" seed ISO for the VM: static networking,
// the desktop user (password + key login + NOPASSWD sudo), the embedded provisioning script and
// the dissector bundle. Mirrors ft_test_env's CloudInitSeed, in Go via kdomanski/iso9660.
func buildSeedIso(c *Config, isoPath string) error {
	bundle, err := buildBundle(c.resolveDissectorDir())
	if err != nil {
		return fmt.Errorf("build dissector bundle: %w", err)
	}

	w, err := iso9660.NewWriter()
	if err != nil {
		return err
	}
	defer w.Cleanup()

	add := func(name, content string) error {
		return w.AddFile(strings.NewReader(content), name)
	}
	if err := add("meta-data", renderMetaData(c)); err != nil {
		return err
	}
	if err := add("user-data", renderUserData(c, bundle)); err != nil {
		return err
	}
	if err := add("network-config", renderNetworkConfig(c)); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(isoPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(isoPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// NoCloud matches the volume identifier "cidata" (case-insensitive).
	return w.WriteTo(f, "cidata")
}

// yq renders s as a double-quoted YAML scalar so config values containing ':', '#', quotes or
// backslashes cannot break (or silently alter) the cloud-init documents.
func yq(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func renderMetaData(c *Config) string {
	return fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", yq(c.VM.Hostname), yq(c.VM.Hostname))
}

func renderNetworkConfig(c *Config) string {
	var b strings.Builder
	b.WriteString("version: 2\n")
	b.WriteString("ethernets:\n")
	b.WriteString("  primary:\n")
	b.WriteString("    match:\n")
	b.WriteString("      name: \"en*\"\n") // enp0s3 etc. under VirtualBox
	fmt.Fprintf(&b, "    addresses: [%s/%d]\n", c.Net.IP, c.Net.PrefixLength)
	b.WriteString("    routes:\n")
	b.WriteString("      - to: default\n")
	fmt.Fprintf(&b, "        via: %s\n", c.Net.Gateway)
	b.WriteString("    nameservers:\n")
	fmt.Fprintf(&b, "      addresses: [%s]\n", c.Net.DNS)
	return b.String()
}

func renderUserData(c *Config, bundle []byte) string {
	scriptB64 := base64.StdEncoding.EncodeToString(setupScript)
	bundleB64 := base64.StdEncoding.EncodeToString(bundle)

	var b strings.Builder
	b.WriteString("#cloud-config\n")
	fmt.Fprintf(&b, "hostname: %s\n", yq(c.VM.Hostname))
	b.WriteString("preserve_hostname: false\n")
	b.WriteString("users:\n")
	fmt.Fprintf(&b, "  - name: %s\n", yq(c.VM.Username))
	fmt.Fprintf(&b, "    plain_text_passwd: %s\n", yq(c.VM.Password))
	b.WriteString("    lock_passwd: false\n")
	b.WriteString("    shell: /bin/bash\n")
	b.WriteString("    sudo: ALL=(ALL) NOPASSWD:ALL\n")
	b.WriteString("    groups: [sudo]\n")
	if key := hostPublicKey(); key != "" {
		b.WriteString("    ssh_authorized_keys:\n")
		fmt.Fprintf(&b, "      - %s\n", key)
	}
	b.WriteString("ssh_pwauth: true\n")
	b.WriteString("package_update: true\n")
	b.WriteString("write_files:\n")
	b.WriteString("  - path: /opt/dissector/setup_linux.sh\n")
	b.WriteString("    permissions: '0755'\n")
	b.WriteString("    encoding: b64\n")
	fmt.Fprintf(&b, "    content: %s\n", scriptB64)
	b.WriteString("  - path: /opt/dissector-bundle.tgz\n")
	b.WriteString("    permissions: '0644'\n")
	b.WriteString("    encoding: b64\n")
	fmt.Fprintf(&b, "    content: %s\n", bundleB64)
	b.WriteString("runcmd:\n")
	b.WriteString("  - [ bash, /opt/dissector/setup_linux.sh ]\n")
	return b.String()
}

// hostPublicKey returns the host's SSH public key (for passwordless manual login), or "".
func hostPublicKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	for _, name := range []string{"id_ed25519.pub", "id_rsa.pub"} {
		if data, err := os.ReadFile(filepath.Join(home, ".ssh", name)); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}
