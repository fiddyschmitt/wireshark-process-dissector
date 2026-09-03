// dissector-test-env stands up an on-demand Debian desktop VM (VirtualBox) with Wireshark and
// the Process Info dissector installed, so the dissector's self-tests can run under real Linux
// Wireshark and a human can verify capture in the Wireshark UI. Same approach as
// file_tunnel/ft_test_env (VBoxManage + a cloud-init NoCloud seed ISO), written in Go.
package main

import (
	"fmt"
	"os"
)

const usage = `dissector-test-env — on-demand Linux desktop VM for the Process Info dissector

Usage: dissector-test-env [-config <file>] <command>

Commands:
  up          Create (if needed) and start the VM in a GUI window, then wait until the
              desktop + Wireshark + dissector are provisioned. Use this to get a machine
              you can click around in.
  up-headless Same as 'up' but no GUI window (for running tests only).
  test        Run the dissector self-tests and a short live capture on the VM over SSH.
  deploy      Push the current local dissector + tests to the running VM (no rebuild).
  status      Show VM state, IP and SSH/provisioning readiness.
  down        Gracefully power the VM off.
  destroy     Power off and delete the VM + its disk + seed ISO (keeps base image).
  create      Build the template + VM without starting it.
  prep        Download the image and build the reusable base.vdi only.
  ssh         Print the ssh command to log in manually.

Typical flow:  up   ->   test   ->  (verify manually in the GUI)  ->  down / destroy
`

func main() {
	args := os.Args[1:]
	configPath := "config.json"
	// crude -config parse (keeps deps minimal)
	var rest []string
	for i := 0; i < len(args); i++ {
		if args[i] == "-config" && i+1 < len(args) {
			configPath = args[i+1]
			i++
			continue
		}
		rest = append(rest, args[i])
	}
	if len(rest) == 0 {
		fmt.Print(usage)
		return
	}

	c, err := LoadConfig(configPath)
	if err != nil {
		fatal(err)
	}
	o := NewOrchestrator(c)

	switch rest[0] {
	case "prep":
		err = o.prep()
	case "create":
		err = o.create()
	case "up":
		err = o.up(true)
	case "up-headless":
		err = o.up(false)
	case "test":
		err = o.test()
	case "deploy":
		err = o.deploy()
	case "down":
		err = o.down()
	case "destroy":
		err = o.destroy()
	case "status":
		err = o.status()
	case "ssh":
		fmt.Printf("ssh %s@%s   (password: see config, default 'live'; your SSH key is also authorised)\n", c.VM.Username, c.Net.IP)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Printf("unknown command %q\n\n", rest[0])
		fmt.Print(usage)
		os.Exit(2)
	}

	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
