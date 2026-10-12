# Yamaha RX-V2500 RS-232C Control

Control a Yamaha **RX-V2500** AV receiver over its rear-panel RS-232C port from Python — via a small CLI, an event-driven MQTT daemon (`rxv2500d`), and automatic **Home Assistant** discovery.

The RX-V2500 predates network control (no IP / YNCA), so this project speaks the receiver's native serial protocol directly. The frames were recovered by reverse-engineering Yamaha's dealer application — full findings in [`docs/YamahaReceiverEditor3_RE_Findings.md`](docs/YamahaReceiverEditor3_RE_Findings.md).

> **Disclaimer:** This project is not affiliated with, endorsed by, or sponsored by Yamaha Corporation. "Yamaha" and model names are trademarks of their respective owners, used here only to describe compatibility. The RS-232C protocol was reverse-engineered for interoperability purposes; no Yamaha proprietary code, firmware, or binaries are distributed in this repository. Everything is provided **as-is with no warranty** — see [License](#license).

## Features

- Power, volume (absolute dB sets and up/down), mute, input select, sound programs, extended surround, sleep timer, night mode, speaker B, Zone 2
- **Event-driven state**: the receiver reports changes on its own (no polling), so state stays accurate without traffic on the wire
- `rxv2500d.py` daemon: ser2net link management, persisted last-known state, MQTT retained topics, LWT availability, Home Assistant auto-discovery
- CLI for one-off commands, raw frame sniffing (`--listen` / `--monitor`) and page queries (`--query`)

## Hardware you need

| Item | Notes |
|---|---|
| **Yamaha RX-V2500** (RX-V1500/V2400/Z-series use the same protocol) | The RS-232C terminal is fitted on U.S.A., Canada, U.K., Europe and Australia models only |
| **Linux host** | A Raspberry Pi (any model with USB, e.g. Zero 2 W / 3 / 4 / 5) or any PC/server |
| **USB → RS-232 serial adapter** | FTDI-based adapters are the most reliable; shows up as `/dev/ttyUSB0`. *(Alternative: a Pi's 40-pin UART header + a MAX3232/MAX232 level-converter board — then the device is `/dev/ttyAMA0` and you must enable the UART with `raspi-config`.)* |
| **DB-9 null-modem cable** (or straight cable + null-modem adapter) | See wiring below. Anything from a few dollars works |

Serial settings: **9600 baud, 8 data bits, no parity, 1 stop bit (8-N-1)**.

### Cable wiring (DE-9, male on the receiver side)

The receiver is wired as a DTE, so you need a null-modem connection with pins 2/3 and 7/8 crossed:

| Signal | Adapter/host pin | RX-V2500 pin |
|---|---|---|
| TXD → | 2 | 3 (RXD) |
| ← RXD | 3 | 2 (TXD) |
| RTS → | 7 | 8 (CTS) |
| ← CTS | 8 | 7 (RTS) |
| GND | 5 | 5 |

The handshake lines aren't strictly required in practice (`ser2net` runs the port with `local`/CLOCAL), but wire them if you're making the cable yourself.

### Architecture

```
RX-V2500 ──RS-232C──▶ USB adapter (/dev/ttyUSB0) ──▶ ser2net ──▶ TCP 127.0.0.1:2500
   (9600 8N1)                                             │
                                                           ▼
                                            rxv2500d.py daemon (sole link owner)
                                                           │
                                                     MQTT broker ──▶ Home Assistant
                                                                     (auto-discovery)
```

## Software setup

### 1. ser2net — expose the serial port as TCP

```bash
sudo apt install ser2net
```

Copy [`examples/ser2net.yaml`](examples/ser2net.yaml) to `/etc/ser2net/ser2net.yaml` (4.x, YAML) or add the one-line entry from that file to `/etc/ser2net.conf` (3.x), then:

```bash
sudo systemctl restart ser2net
```

> **Important:** ser2net opens `/dev/ttyUSB0` when the first TCP client connects and closes it when the last one leaves. Exactly **one** process may own the link — that's what `rxv2500d.py` is for. Don't run the CLI while the daemon is connected.

### 2. Test the link with the CLI

```bash
pip3 install paho-mqtt          # only needed for the MQTT tools
python3 yamaha_rs232_controller.py localhost power_on     # receiver turns on
python3 yamaha_rs2500d.py --help                           # daemon help
python3 yamaha_rs232_controller.py --query localhost       # dump data pages
python3 yamaha_rs232_controller.py --listen localhost 10   # sniff raw reports
```

Run `python3 yamaha_rs232_controller.py` with no arguments to list every supported command.

### 3. Run the MQTT daemon (recommended)

```bash
sudo mkdir -p /var/lib/rxv2500d
cp examples/rxv2500d.conf /etc/rxv2500d.conf
$EDITOR /etc/rxv2500d.conf      # set MQTT_HOST (+ MQTT_USER/MQTT_PASS if needed)
python3 rxv2500d.py --config /etc/rxv2500d.conf -v
```

On connect the daemon waits for the receiver's connection dump, seeds its state, and publishes Home Assistant discovery configs. Every config key can also be overridden with an `RXV2500D_`-prefixed environment variable (e.g. `RXV2500D_MQTT_PASS`).

As a service: see [`examples/rxv2500d.service`](examples/rxv2500d.service).

### 4. Home Assistant

Nothing to configure — once the daemon connects to your broker, the RX-V2500 appears automatically as a media player plus selector entities (input, sound mode, …).

MQTT topics (root `rxv2500/` by default):

| Topic | Direction | Meaning |
|---|---|---|
| `rxv2500/availability` | daemon → | `online` / `offline` (LWT) |
| `rxv2500/link` | daemon → | `ON` / `OFF` — TCP link to ser2net |
| `rxv2500/state/<field>` | daemon → | retained per-field state (`power`, `volume`, `input`, …) |
| `rxv2500/state` | daemon → | retained full JSON state |
| `rxv2500/set/<field>` | → daemon | set a field: `power`, `input`, `volume`, `volume_db`, `mute`, `straight`, `speaker_b`, `sound_program`, `ext_surround`, `sleep`, `night_mode` |
| `rxv2500/cmd/reseed` | → daemon | force reconnect (optionally restart ser2net) to get a fresh dump |

Example:

```bash
mosquitto_pub -t rxv2500/set/power -m 'on'
mosquitto_pub -t rxv2500/set/volume_db -m '-35.5'
```

### Simple bridge alternative

[`yamaha_mqtt_bridge.py`](yamaha_mqtt_bridge.py) is a minimal poll-free bridge kept as a starting point; `rxv2500d.py` supersedes it. Configure broker/credentials via the constants at the top or matching environment variables (`MQTT_BROKER`, `MQTT_USER`, `MQTT_PASS`, …).

## Protocol cheat-sheet

- Frame: `STX (0x02) + ASCII payload + ETX (0x03)`
- **Full-record** commands: 5 ASCII chars, e.g. power on = `\x0207A1D\x03`
- **Prefix+value** commands: 3-char prefix + 2 uppercase hex digits, e.g. main volume `\x02230<HH>\x03`
- Volume wire byte = `raw + 0x27` (raw = half-dB above −80.0), with `0x00` meaning mute-off-zero; panel-calibrated — the original Windows app's constant (0x26) is off by one
- The receiver answers inquiries with bare ACKs and pushes **state reports** on change; type `0x30` frames are echoes/group status, never state
- Power commands work from standby; other commands only while powered on

See [`docs/YamahaReceiverEditor3_RE_Findings.md`](docs/YamahaReceiverEditor3_RE_Findings.md) for the full reverse-engineering write-up (frame builder, command-ID table mapping, report decoding).

## Files

```
yamaha_rs232_controller.py   core protocol library + CLI (frames, commands, report parser)
rxv2500d.py                  resident RS-232 → MQTT daemon with HA discovery (recommended)
yamaha_mqtt_bridge.py        minimal legacy MQTT bridge
docs/…_RE_Findings.md        reverse-engineering notes for the protocol
examples/                    ser2net, daemon config + systemd unit templates
```

## Notes & safety

- There is deliberately **no volume probe** on startup: `vol_down` is a no-op on this receiver, so old "net-zero" probes leaked +0.5 dB per restart. Volume state is restored from the persisted file and refreshed by user-generated reports.
- Absolute volume sets (`230`) are applied silently — the receiver echoes but never reports them; the daemon updates its own state optimistically.
- If the link dies (Pi reboot, USB hiccup), publish to `rxv2500/cmd/reseed` or restart the daemon to force a fresh connection dump.

## Credits

Credit where credit is due: **all source code, documentation, and reverse-engineering analysis in this repository were written by AI**. The project was built with AI coding agents running in [OpenCode](https://opencode.ai) — the agent(s) authored every Python file, performed the disassembly/analysis of Yamaha's dealer application, drafted these docs, and ran the tooling.

The human role was direction and reality-checking: defining goals, prompting and steering each iteration, wiring the hardware, and verifying against a real RX-V2500 (front-panel volume readings that settled the `0x27` offset calibration, confirming commands actually did what the frames said they did).

Consider this repo both a working home-automation bridge and an artifact of how far fully AI-assisted development has come.

## License

Distributed under the **Apache License 2.0** — see [LICENSE](LICENSE).
