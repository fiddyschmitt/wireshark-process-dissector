package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshConfig builds a password-auth client config for the desktop user. Host-key checking is
// disabled: these are ephemeral lab VMs on the local LAN.
func sshClientConfig(c *Config) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            c.VM.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(c.VM.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         6 * time.Second,
	}
}

func dialSSH(c *Config) (*ssh.Client, error) {
	addr := net.JoinHostPort(c.Net.IP, fmt.Sprint(c.VM.SSHPort))
	return ssh.Dial("tcp", addr, sshClientConfig(c))
}

// waitForSSH blocks until an SSH login succeeds or the timeout elapses.
func waitForSSH(c *Config, timeout time.Duration, log func(string)) error {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		client, err := dialSSH(c)
		if err == nil {
			client.Close()
			return nil
		}
		last = err
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("no SSH within %s (%v)", timeout, last)
}

// runSSH runs one command over a fresh connection and returns combined stdout, exit-ok, stderr.
func runSSH(c *Config, command string) (string, string, error) {
	client, err := dialSSH(c)
	if err != nil {
		return "", "", err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer sess.Close()
	var out, errb bytes.Buffer
	sess.Stdout = &out
	sess.Stderr = &errb
	runErr := sess.Run(command)
	return out.String(), errb.String(), runErr
}

// uploadFile streams data to remotePath over SSH (no sftp dependency: pipe into `cat`).
func uploadFile(c *Config, data []byte, remotePath string) error {
	client, err := dialSSH(c)
	if err != nil {
		return err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	var errb bytes.Buffer
	sess.Stderr = &errb
	if err := sess.Run("cat > " + shellQuote(remotePath)); err != nil {
		return fmt.Errorf("upload %s: %v: %s", remotePath, err, errb.String())
	}
	return nil
}

// waitForProvisioned polls until the setup script's completion sentinel appears.
func waitForProvisioned(c *Config, timeout time.Duration, log func(string)) error {
	deadline := time.Now().Add(timeout)
	lastNote := ""
	for time.Now().Before(deadline) {
		out, _, err := runSSH(c, "{ test -f /run/dissector-setup-complete || test -f /var/lib/dissector/setup-complete; } && echo READY || tail -n1 /var/log/dissector-setup.log 2>/dev/null")
		if err == nil {
			if strings.Contains(out, "READY") {
				return nil
			}
			if note := strings.TrimSpace(out); note != "" && note != lastNote {
				lastNote = note
				if log != nil {
					log("  ... " + truncate(note, 100))
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("provisioning did not complete within %s", timeout)
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func truncate(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

var _ = io.Discard
