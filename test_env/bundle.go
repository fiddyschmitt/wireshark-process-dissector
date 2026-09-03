package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// wiresharkPreferences is the packet-list column layout deployed into the guest, matching the
// columns configured on the other machines (PID, Process, Side, Exe file, Exe folder).
const wiresharkPreferences = `# Wireshark preferences
# Process Info columns from process_dissector.lua (deployed by the test-VM orchestrator).

######## User Interface: Columns ########

# Packet list column format
gui.column.format:
	"No.", "%m",
	"Time", "%t",
	"Source", "%s",
	"Destination", "%d",
	"Protocol", "%p",
	"Length", "%L",
	"PID", "%Cus:process.pid:0:R",
	"Process", "%Cus:process.name:0:R",
	"Side", "%Cus:process.side:0:R",
	"Exe file", "%Cus:process.filename:0:R",
	"Exe folder", "%Cus:process.folder:0:R",
	"Info", "%i"
`

// buildBundle packs the dissector into a .tgz laid out for the guest:
//
//	process_dissector.lua        (the plugin + the file tests/ loads as ../process_dissector.lua)
//	preferences                  (Wireshark column layout)
//	tests/run_tests.lua          (self-test runner)
//	tests/empty.pcap             (empty capture the runner reads)
//	tests/fixtures/*             (canned OS outputs the parser tests assert against)
//
// It reads the sources fresh from dissectorDir each call, so create/deploy always ship the
// current version.
func buildBundle(dissectorDir string) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	addBytes := func(name string, data []byte, mode int64) error {
		hdr := &tar.Header{Name: name, Mode: mode, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: time.Now()}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	addFile := func(name, srcPath string, mode int64) error {
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return fmt.Errorf("read %s: %w", srcPath, err)
		}
		return addBytes(name, data, mode)
	}

	main := filepath.Join(dissectorDir, "process_dissector.lua")
	if err := addFile("process_dissector.lua", main, 0o644); err != nil {
		return nil, err
	}
	if err := addBytes("preferences", []byte(wiresharkPreferences), 0o644); err != nil {
		return nil, err
	}

	// Everything under tests/ (run_tests.lua, empty.pcap, fixtures/*).
	testsDir := filepath.Join(dissectorDir, "tests")
	if info, err := os.Stat(testsDir); err == nil && info.IsDir() {
		walkErr := filepath.WalkDir(testsDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "out" { // scratch dir the runner writes; skip
					return fs.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(dissectorDir, path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			return addFile(rel, path, 0o644)
		})
		if walkErr != nil {
			return nil, walkErr
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
