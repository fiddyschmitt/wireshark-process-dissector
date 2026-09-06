# wireshark-process-dissector

See which process sent or received each packet in Wireshark, and filter on it.

Windows, Linux and macOS. A single Lua file.

<img src="img/columns.png" width="800">

## Download

Get `process_dissector.lua` from the [releases](https://github.com/fiddyschmitt/wireshark-process-dissector/releases/latest) section and copy it to your personal Lua plugins folder (Help → About Wireshark → Folders → Personal Lua Plugins). Restart Wireshark.

## Fields

| Field | Description |
|---|---|
| `process.pid` | Process ID |
| `process.name` | Process name |
| `process.path` | Executable full path |
| `process.folder` | Executable folder |
| `process.filename` | Executable filename |
| `process.cmdline` | Command line |
| `process.side` | `src` or `dst` — which end of the packet the process owns |

## Examples

```
process.name == "chrome.exe"
process.path contains "python"
process.cmdline contains "--proxy"
process.side == "src" && process.pid == 1234
```

To show a field as a column, right-click it in the packet details and choose *Apply as Column*.

## How it works

Packets carry no process information, so the dissector maps each packet's local endpoint to the socket table.

- **Windows / macOS**: a small helper (embedded in the Lua file) runs hidden, polls the socket table every 250 ms, and exits when Wireshark closes.
- **Linux**: reads `/proc` directly. No helper.

Long-lived connections resolve reliably. A socket that opens and closes between two polls can be missed. Other users' processes need root / admin (see Preferences → Protocols → Process Info).

On **Windows, when Wireshark runs elevated**, the helper also consumes Kernel-Network connect/accept events, so short-lived connections between polls are caught too. It enables an isolated, bounded, circular Analytic log while capturing and disables it on exit — no persistent change. Turn it off with the "use connection events when elevated" preference.

## Tests

```
tshark -X lua_script:tests/run_tests.lua -r tests/empty.pcap
```

Live-capture checks are in `tests/live/` (`exact_mode_check.ps1` validates the elevated Windows path). `test_env/` stands up a throwaway Linux desktop VM for testing.
