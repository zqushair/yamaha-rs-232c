#!/usr/bin/env python3
"""
rxv2500d — resident daemon bridging the Yamaha RX-V2500 RS-232 link to MQTT.

Phase B of the RX-V2500 / Home Assistant project.  Design notes:

* Sole owner of the ser2net TCP link (localhost:2500).  ser2net opens
  /dev/ttyUSB0 when the first TCP client connects and closes it when the
  last one leaves, so exactly ONE process may hold the connection.
* State is event driven: the receiver answers inquiries with bare ACKs
  only (no polling), so state = connection dump (when one arrives) +
  accumulated change reports + the persisted last-known state file.
* Commands are serialized through one worker queue.  Acknowledgement is
  the matching state report (type != 0x30 — type 0x30 frames are group
  status / command echoes and never state).  A timeout is logged; only
  power commands get a retry (the receiver can swallow the first frame
  while waking) and an inquiry-based fallback resolution.
* MQTT: retained per-field state topics, HA discovery configs under
  homeassistant/<component>/rxv2500/<object>/config, LWT availability.

Topics (root configurable, default "rxv2500"):
  rxv2500/availability           online/offline (LWT — daemon <-> broker)
  rxv2500/link                   ON/OFF (daemon <-> ser2net TCP link)
  rxv2500/state/<field>          retained per-field state
  rxv2500/state                  retained full JSON state
  rxv2500/set/<field>            command topics
  rxv2500/cmd/reseed             force reconnect (+ optional ser2net restart)

Safety: the only automatic receiver traffic is (a) reading reports and
(b) a bare-ACK liveness inquiry. There is deliberately NO volume probe:
vol_down (07A1B) is a no-op on this receiver, so the old "net-zero"
vol_down+vol_up probe leaked +0.5 dB on every restart. Volume state is
restored from the persisted file, refreshed by user-generated reports,
and updated optimistically by our own silent "230" sets (the receiver
acknowledges those with an echo only — never a state report).
"""

import argparse
import json
import logging
import os
import queue
import re
import signal
import socket
import subprocess
import sys
import threading
import time

import paho.mqtt.client as mqtt

from yamaha_rs232_controller import (
    EXT_SURROUND_NAMES,
    INPUT_NAMES,
    INPUT_RECORDS,
    NIGHT_MODE_NAMES,
    ReportParser,
    SLEEP_NAMES,
    SOUND_PROGRAM_NAMES,
    VOLUME_WIRE_OFFSET,
    YamahaController,
    build_full_record_command,
)

LOG = logging.getLogger('rxv2500d')

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    'MQTT_HOST': 'localhost',
    'MQTT_PORT': '1883',
    'MQTT_USER': '',
    'MQTT_PASS': '',
    'CLIENT_ID': 'rxv2500d',
    'ROOT': 'rxv2500',
    'DISCOVERY_PREFIX': 'homeassistant',
    'SERIAL_HOST': 'localhost',
    'SERIAL_PORT': '2500',
    'STATE_FILE': 'rxv2500d_state.json',
    'DUMP_WAIT': '8',               # seconds to wait for a connection dump
    'SEED_REFRESH_INPUT': 'false',  # resend stored input (can change input!)
    'RESEED_RESTART_SER2NET': 'false',
    'LOG_LEVEL': 'INFO',
}

TRUE_VALUES = {'ON', 'TRUE', '1', 'YES'}
FALSE_VALUES = {'OFF', 'FALSE', '0', 'NO'}

INQUIRY = b'\x0220100\x03'   # data-page inquiry: bare ACK when powered on

# Discovery artifacts from pre-1.3 bring-up iterations (early experiments
# published these under ad-hoc topics before the current rxv2500/ scheme).
# HA keeps such entities undeletable in its UI while their retained config
# exists, so _publish_discovery clears them with empty retained payloads.
LEGACY_DISCOVERY_TOPICS = (
    'select/yamaha_input/config',
    'select/yamaha_sound_mode/config',
    'media_player/yamaha_rxv2500/config',
    'media_player/yamaha_rxv2500/state',
)


def load_config(path):
    cfg = dict(DEFAULT_CONFIG)
    if path and os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, _, val = line.partition('=')
                    cfg[key.strip().upper()] = val.strip()
    for key in list(cfg):                       # RXV2500D_* env overrides
        env = os.environ.get('RXV2500D_' + key)
        if env is not None:
            cfg[key] = env
    return cfg


def cfg_bool(cfg, key):
    return cfg.get(key, '').strip().upper() in TRUE_VALUES


def norm(text):
    """Normalize a command payload for table lookup."""
    return re.sub(r'[\s\-]+', '_', text.strip().upper())


def parse_bool(text):
    up = text.strip().upper()
    if up in TRUE_VALUES:
        return True
    if up in FALSE_VALUES:
        return False
    raise ValueError('expected ON/OFF, got %r' % text)


# ---------------------------------------------------------------------------
# Command tables (verified records only — the controller's legacy dict has
# duplicate keys from old bulk imports, so the daemon does not use it)
# ---------------------------------------------------------------------------

def full(record):
    return build_full_record_command(record)


VALUE_TO_INPUT_RECORD = {}
for _rec, _val in INPUT_RECORDS.items():        # first record wins (canonical)
    VALUE_TO_INPUT_RECORD.setdefault(_val, _rec)

INPUT_BY_NORM = {norm(name): val for val, name in INPUT_NAMES.items()}
PROGRAM_BY_NORM = {norm(name): val for val, name in SOUND_PROGRAM_NAMES.items()}

# Program value -> select record (all 20 verified against SOUND_PROGRAM_NAMES)
PROGRAM_TO_RECORD = {
    0x00: '07EE1',   # HALL_MUNICH
    0x05: '07EE5',   # HALL_VIENNA
    0x09: '07EE8',   # HALL_FREIBURG
    0x0E: '07EEC',   # HALL_BOTTOM_LINE
    0x10: '07EED',   # HALL_ROXY
    0x14: '07EF0',   # DISCO
    0x16: '07EF2',   # GAME
    0x17: '07EFF',   # STEREO_7CH
    0x18: '07EF3',   # POP_ROCK
    0x1C: '07EF5',   # CLASSICAL
    0x20: '07EF7',   # MONO_MOVIE
    0x21: '07EF8',   # TV_SPORTS
    0x24: '07EF9',   # SPECTACLE
    0x25: '07EFA',   # SCI_FI
    0x28: '07EFB',   # ADVENTURE
    0x29: '07EFC',   # GENERAL
    0x2C: '07EFD',   # PRO_LOGIC
    0x2D: '07EFE',   # PRO_LOGIC_ENHANCED
    0x34: '07EC0',   # STEREO_2CH
    0x36: '07EC2',   # THX_CINEMA
}

EXT_TO_RECORD = {                       # normalized name -> record
    'OFF': '07EB9',
    'ES/EX': '07E7D',
    'AUTO': '07E7C',
    'PLIIX_MOVIE': '07EDD',
    'PLIIX_MUSIC': '07EDE',
}
NIGHT_TO_RECORD = {
    'OFF': '07E9C',
    'CINEMA_MID': '07E9B',
    'MUSIC_MID': '07ECF',
}
SLEEP_TO_RECORD = {
    'OFF': '07EB3',
    '120MIN': '07EB4', '120_MIN': '07EB4', '120': '07EB4',
    '90MIN': '07EB5', '90_MIN': '07EB5', '90': '07EB5',
    '60MIN': '07EB6', '60_MIN': '07EB6', '60': '07EB6',
    '30MIN': '07EB7', '30_MIN': '07EB7', '30': '07EB7',
}

CTRL = {
    'power_on': full('07A1D'),
    'power_off': full('07A1E'),
    'vol_up': full('07A1A'),
    'vol_down': full('07A1B'),
    'mute_on': full('07EA2'),
    'mute_off': full('07EA3'),
    'straight_on': full('07EE0'),
    'straight_off': full('07E27'),
    'speaker_b_on': full('07EAD'),
    'speaker_b_off': full('07EAE'),
}


def state_pred(expect):
    """A genuine state report for `expect`: any type except 0x30."""
    return lambda r: r.get('type') != 0x30 and r.get('id') == expect


def ack_pred(r):
    """Bare ACK for inquiry frames (30 00 00)."""
    return r.get('type') == 0x30 and r.get('id') == 0x00 and r.get('value') == 0


def echo_pred(expect, wire):
    return (lambda r: r.get('type') == 0x30 and r.get('id') == expect
            and r.get('value') == wire)


# ---------------------------------------------------------------------------
# State store
# ---------------------------------------------------------------------------

class StateStore:
    """Thread-safe receiver state + report wait/notify."""

    def __init__(self, state_file):
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.parser = ReportParser()
        self.state_file = state_file
        self.groups = {}
        self.seq = 0                 # increments on every parsed report
        self.recent = []             # (seq, report) history for wait()
        self.link = False            # TCP link up?
        self.generation = 0          # bumped on every (re)connect
        self._dirty = False
        self._last_write = 0.0
        self._stop = threading.Event()
        self.load()

    # -- persistence --------------------------------------------------------
    def load(self):
        if not self.state_file or not os.path.exists(self.state_file):
            LOG.info('no state file at %s — starting empty', self.state_file)
            return
        try:
            with open(self.state_file) as fh:
                data = json.load(fh)
            saved = data.get('state', {})
            for key in self.parser.state:
                if key in saved:
                    self.parser.state[key] = saved[key]
            self.groups = {int(k): v for k, v in data.get('groups', {}).items()}
            known = [k for k, v in self.parser.state.items() if v is not None]
            LOG.info('restored persisted state (%s) from %s',
                     ', '.join(known), self.state_file)
        except Exception as exc:
            LOG.warning('could not load state file: %s', exc)

    def persist(self):
        if not self.state_file:
            return
        with self.lock:
            payload = {
                'saved_at': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                'state': self.parser.state,
                'groups': self.groups,
            }
            self._dirty = False
            self._last_write = time.monotonic()
        try:
            tmp = self.state_file + '.tmp'
            with open(tmp, 'w') as fh:
                json.dump(payload, fh, indent=1)
            os.replace(tmp, self.state_file)
        except Exception as exc:
            LOG.warning('state persist failed: %s', exc)

    def mark_dirty(self):
        with self.lock:
            self._dirty = True

    def flusher(self):
        """Write the state file at most once per second."""
        while not self._stop.wait(1.0):
            with self.lock:
                dirty = self._dirty
            if dirty:
                self.persist()

    def stop(self):
        self._stop.set()
        self.persist()

    # -- reports ------------------------------------------------------------
    def ingest(self, frame):
        with self.cond:
            report = self.parser.parse_frame(frame)
            if report is None:
                return None
            self.seq += 1
            self.recent.append((self.seq, report))
            if len(self.recent) > 300:
                del self.recent[:150]
            if len(self.parser.raw_log) > 500:
                del self.parser.raw_log[:250]
            if report.get('type') == 0x30 and report.get('id') not in (0x00, 0x26):
                self.groups[report['id']] = report['value']
            self.cond.notify_all()
            return report

    def wait(self, pred, after_seq, timeout, alive=None):
        """Wait for a report matching pred with seq > after_seq."""
        deadline = time.monotonic() + timeout
        with self.cond:
            while True:
                if alive is not None and not alive():
                    return None
                for seq, rep in self.recent:
                    if seq > after_seq and pred(rep):
                        return rep
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.cond.wait(min(remaining, 0.5))

    def poll(self, pred, after_seq):
        with self.cond:
            for seq, rep in self.recent:
                if seq > after_seq and pred(rep):
                    return rep
            return None

    @property
    def current_seq(self):
        with self.cond:
            return self.seq


# ---------------------------------------------------------------------------
# Serial link (sole owner of the ser2net TCP connection)
# ---------------------------------------------------------------------------

def extract_frames(buf):
    """Split a byte stream on STX..ETX frames.  Returns (frames, rest)."""
    frames = []
    while True:
        stx = buf.find(b'\x02')
        if stx == -1:
            return frames, b''
        if stx:
            buf = buf[stx:]               # drop junk before STX
        etx = buf.find(b'\x03', 1)
        if etx == -1:
            return frames, buf            # incomplete frame — wait for more
        frames.append(buf[:etx + 1])
        buf = buf[etx + 1:]


class SerialLink(threading.Thread):
    """Maintains the persistent TCP connection; parses frames to a callback."""

    def __init__(self, host, port, on_frame, on_connect, on_disconnect,
                 restart_ser2net=False):
        super().__init__(name='serial', daemon=True)
        self.host = host
        self.port = port
        self.on_frame = on_frame
        self.on_connect = on_connect
        self.on_disconnect = on_disconnect
        self.restart_ser2net = restart_ser2net
        self._stop = threading.Event()
        self._reseed = threading.Event()
        self._send_lock = threading.Lock()
        self._sock = None

    def run(self):
        backoff = 1.0
        while not self._stop.is_set():
            if self._reseed.is_set() and self.restart_ser2net:
                self._reseed.clear()
                LOG.info('reseed: restarting ser2net to force a serial reopen')
                try:
                    subprocess.run(
                        ['sudo', '-n', 'systemctl', 'restart', 'ser2net'],
                        timeout=15, capture_output=True)
                except Exception as exc:
                    LOG.warning('ser2net restart failed: %s', exc)
                time.sleep(1.0)
            else:
                self._reseed.clear()

            try:
                sock = socket.create_connection((self.host, self.port), timeout=5)
            except OSError as exc:
                LOG.warning('connect %s:%s failed: %s (retry in %.0fs)',
                            self.host, self.port, exc, backoff)
                if not self._stop.wait(backoff):
                    backoff = min(backoff * 2, 30.0)
                continue
            backoff = 1.0
            sock.settimeout(0.5)
            self._sock = sock
            LOG.info('connected to %s:%s', self.host, self.port)
            try:
                self.on_connect()
            except Exception:
                LOG.exception('on_connect hook failed')

            buf = b''
            try:
                while not self._stop.is_set() and not self._reseed.is_set():
                    try:
                        data = sock.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if not data:
                        LOG.info('peer closed the connection')
                        break
                    buf += data
                    frames, buf = extract_frames(buf)
                    for frame in frames:
                        try:
                            self.on_frame(frame)
                        except Exception:
                            LOG.exception('frame handler failed: %s',
                                          frame.hex(' '))
            finally:
                with self._send_lock:
                    try:
                        sock.close()
                    except OSError:
                        pass
                if self._sock is sock:
                    self._sock = None
                LOG.info('disconnected')
                try:
                    self.on_disconnect()
                except Exception:
                    LOG.exception('on_disconnect hook failed')

            if not self._stop.is_set():
                if not self._stop.wait(0.3):
                    continue
        # final close on stop
        with self._send_lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def send(self, data):
        with self._send_lock:
            if self._sock is None:
                raise ConnectionError('serial link is down')
            self._sock.sendall(data)

    def request_reseed(self):
        LOG.info('reseed requested')
        self._reseed.set()
        with self._send_lock:
            if self._sock is not None:
                try:
                    self._sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def stop(self):
        self._stop.set()
        with self._send_lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.root = cfg['ROOT'].strip('/')
        self.store = StateStore(cfg['STATE_FILE'])
        self.jobs = queue.Queue()
        self._stop = threading.Event()
        self._sent = {}                  # topic -> last payload
        self._sent_lock = threading.Lock()
        self._broker_up = False

        self.mqtt_client = self._make_mqtt_client()
        self.link = SerialLink(
            cfg['SERIAL_HOST'], int(cfg['SERIAL_PORT']),
            on_frame=self._on_frame, on_connect=self._on_link_up,
            on_disconnect=self._on_link_down,
            restart_ser2net=cfg_bool(cfg, 'RESEED_RESTART_SER2NET'))

    # -- MQTT ---------------------------------------------------------------
    def _make_mqtt_client(self):
        try:
            from paho.mqtt.enums import CallbackAPIVersion
            client = mqtt.Client(CallbackAPIVersion.VERSION2,
                                 client_id=self.cfg['CLIENT_ID'])
        except (ImportError, AttributeError):
            client = mqtt.Client(client_id=self.cfg['CLIENT_ID'])
        if self.cfg['MQTT_USER']:
            client.username_pw_set(self.cfg['MQTT_USER'], self.cfg['MQTT_PASS'])
        client.will_set(f'{self.root}/availability', 'offline',
                        qos=1, retain=True)
        client.on_connect = self._mqtt_on_connect
        client.on_disconnect = self._mqtt_on_disconnect
        client.on_message = self._mqtt_on_message
        return client

    def start(self):
        self.link.start()
        threading.Thread(target=self.store.flusher, name='flusher',
                         daemon=True).start()
        threading.Thread(target=self._worker, name='cmd-worker',
                         daemon=True).start()
        host, port = self.cfg['MQTT_HOST'], int(self.cfg['MQTT_PORT'])
        LOG.info('connecting to MQTT broker %s:%s', host, port)
        self.mqtt_client.connect_async(host, port, keepalive=60)
        self.mqtt_client.loop_start()

    def pub(self, topic, payload, retain=True):
        payload = str(payload)
        if self._sent.get(topic) == payload:
            return
        try:
            info = self.mqtt_client.publish(topic, payload, qos=0, retain=retain)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                return
            with self._sent_lock:
                self._sent[topic] = payload
        except Exception as exc:
            LOG.debug('publish failed: %s', exc)

    def _pub_force(self, topic, payload, retain=True):
        with self._sent_lock:
            self._sent.pop(topic, None)
        self.pub(topic, payload, retain)

    def _mqtt_on_connect(self, client, userdata, flags, reason_code,
                         properties=None):
        if hasattr(reason_code, 'is_failure'):
            failed = reason_code.is_failure
        else:
            failed = reason_code != 0
        if failed:
            LOG.error('MQTT connect failed: %s', reason_code)
            return
        LOG.info('MQTT connected')
        self._broker_up = True
        client.subscribe(f'{self.root}/set/#', qos=1)
        client.subscribe(f'{self.root}/cmd/#', qos=1)
        self._publish_availability()
        self._pub_force(f'{self.root}/link',
                        'ON' if self.store.link else 'OFF')
        self._publish_discovery()
        self.publish_state(force=True)

    def _mqtt_on_disconnect(self, client, userdata, *args):
        self._broker_up = False
        LOG.warning('MQTT disconnected')

    def _mqtt_on_message(self, client, userdata, msg):
        payload = msg.payload.decode('utf-8', 'replace').strip()
        topic = msg.topic
        if topic == f'{self.root}/cmd/reseed':
            LOG.info('reseed command received')
            self.link.request_reseed()
            return
        prefix = f'{self.root}/set/'
        if not topic.startswith(prefix):
            return
        field = topic[len(prefix):]
        try:
            job = self.build_job(field, payload)
        except ValueError as exc:
            LOG.warning('rejected %s=%r: %s', field, payload, exc)
            return
        LOG.info('queue %s (%r)', job['name'], payload)
        self.jobs.put(job)

    def _publish_availability(self):
        """Broker connection status (LWT covers crashes on the broker side)."""
        topic = f'{self.root}/availability'
        with self._sent_lock:
            self._sent.pop(topic, None)
        self.mqtt_client.publish(topic, 'online', qos=1, retain=True)
        with self._sent_lock:
            self._sent[topic] = 'online'

    def _publish_discovery(self):
        cfg, root = self.cfg, self.root
        prefix = cfg['DISCOVERY_PREFIX'].rstrip('/')
        dev = {
            'identifiers': ['yamaha_rxv2500'],
            'name': 'Yamaha RX-V2500',
            'manufacturer': 'Yamaha',
            'model': 'RX-V2500',
            'sw_version': 'rxv2500d',
        }
        base = {'avty_t': f'{root}/availability', 'dev': dev, 'qos': 0}

        entities = []

        for obj, name, field in (
            ('power', 'Power', 'power'),
            ('mute', 'Mute', 'mute'),
            ('straight', 'Straight', 'straight'),
            ('speaker_b', 'Speaker B', 'speaker_b'),
        ):
            entities.append((f'switch/rxv2500/{obj}', {
                **base, 'name': name, 'uniq_id': f'rxv2500_{obj}',
                'stat_t': f'{root}/state/{field}',
                'cmd_t': f'{root}/set/{field}',
                'pl_on': 'ON', 'pl_off': 'OFF',
            }))

        selects = [
            ('input', 'Input',
             [INPUT_NAMES[v] for v in sorted(INPUT_NAMES)]),
            ('sound_program', 'Sound Program',
             [SOUND_PROGRAM_NAMES[v] for v in sorted(SOUND_PROGRAM_NAMES)]),
            ('ext_surround', 'Extended Surround',
             [EXT_SURROUND_NAMES[v] for v in sorted(EXT_SURROUND_NAMES)]),
            ('sleep', 'Sleep Timer',
             ['OFF', '30min', '60min', '90min', '120min']),
            ('night_mode', 'Night Mode',
             ['OFF', 'CINEMA_MID', 'MUSIC_MID']),
        ]
        for obj, name, options in selects:
            entities.append((f'select/rxv2500/{obj}', {
                **base, 'name': name, 'uniq_id': f'rxv2500_{obj}',
                'stat_t': f'{root}/state/{obj}',
                'cmd_t': f'{root}/set/{obj}',
                'options': options,
            }))

        entities.append(('number/rxv2500/volume', {
            **base, 'name': 'Volume', 'uniq_id': 'rxv2500_volume',
            'stat_t': f'{root}/state/volume_db',
            'cmd_t': f'{root}/set/volume_db',
            'min': -80, 'max': 14, 'step': 0.5, 'mode': 'slider',
            'unit_of_meas': 'dB',
        }))

        entities.append(('binary_sensor/rxv2500/pure_direct', {
            **base, 'name': 'Pure Direct', 'uniq_id': 'rxv2500_pure_direct',
            'stat_t': f'{root}/state/pure_direct',
            'pl_on': 'ON', 'pl_off': 'OFF',
        }))
        entities.append(('binary_sensor/rxv2500/link', {
            **base, 'name': 'Receiver Link', 'uniq_id': 'rxv2500_link',
            'stat_t': f'{root}/link', 'device_class': 'connectivity',
            'pl_on': 'ON', 'pl_off': 'OFF',
        }))
        entities.append(('button/rxv2500/reseed', {
            **base, 'name': 'Reseed', 'uniq_id': 'rxv2500_reseed',
            'cmd_t': f'{root}/cmd/reseed', 'payload_press': '',
        }))

        for obj_path, payload in entities:
            topic = f'{prefix}/{obj_path}/config'
            self._pub_force(topic, json.dumps(payload))
        LOG.info('published %d discovery configs', len(entities))

        for legacy in LEGACY_DISCOVERY_TOPICS:
            self._pub_force(f'{prefix}/{legacy}', '')
        LOG.info('cleared %d legacy discovery topics', len(LEGACY_DISCOVERY_TOPICS))

    # -- state publishing ---------------------------------------------------
    @staticmethod
    def _onoff(value):
        return 'ON' if value else 'OFF'

    @staticmethod
    def _db(value):
        return f'{value:.1f}'

    def publish_state(self, force=False):
        with self.store.lock:
            s = dict(self.store.parser.state)
            groups = dict(self.store.groups)

        out = {}
        if s.get('power') is not None:
            out[f'{self.root}/state/power'] = self._onoff(s['power'])
        if s.get('input_name'):
            out[f'{self.root}/state/input'] = s['input_name']
        if s.get('volume_db') is not None:
            out[f'{self.root}/state/volume_db'] = self._db(s['volume_db'])
        if s.get('volume') is not None:
            out[f'{self.root}/state/volume'] = str(s['volume'])
        if s.get('mute') is not None:
            out[f'{self.root}/state/mute'] = self._onoff(s['mute'])
        if s.get('straight') is not None:
            out[f'{self.root}/state/straight'] = self._onoff(s['straight'])
        if s.get('sound_program'):
            out[f'{self.root}/state/sound_program'] = s['sound_program']
        if s.get('ext_surround') is not None:
            out[f'{self.root}/state/ext_surround'] = EXT_SURROUND_NAMES.get(
                s['ext_surround'], f"0x{s['ext_surround']:02X}")
        if s.get('sleep') is not None:
            out[f'{self.root}/state/sleep'] = SLEEP_NAMES.get(
                s['sleep'], f"0x{s['sleep']:02X}")
        if s.get('night_mode') is not None:
            out[f'{self.root}/state/night_mode'] = NIGHT_MODE_NAMES.get(
                s['night_mode'], f"0x{s['night_mode']:02X}")
        if s.get('speaker_b') is not None:
            out[f'{self.root}/state/speaker_b'] = self._onoff(s['speaker_b'])
        pd = s.get('pure_direct')
        if pd is None:
            pd = s.get('input_pure_direct')
        if pd is not None:
            out[f'{self.root}/state/pure_direct'] = self._onoff(pd)

        blob = json.dumps({
            'state': s,
            'groups': {f'0x{k:02X}': v for k, v in groups.items()},
            'updated': time.strftime('%Y-%m-%dT%H:%M:%S%z'),
        })
        out[f'{self.root}/state'] = blob

        for topic, payload in out.items():
            if force:
                self._pub_force(topic, payload)
            else:
                self.pub(topic, payload)

    # -- link events --------------------------------------------------------
    def _on_link_up(self):
        with self.store.lock:
            self.store.link = True
            self.store.generation += 1
        self._pub_force(f'{self.root}/link', 'ON')
        self.publish_state(force=True)
        threading.Thread(target=self._seed, name='seed', daemon=True).start()

    def _on_link_down(self):
        with self.store.lock:
            self.store.link = False
            self.store.generation += 1
        self._pub_force(f'{self.root}/link', 'OFF')
        self.store.mark_dirty()

    def _on_frame(self, frame):
        report = self.store.ingest(frame)
        if report is None:
            LOG.debug('ignored frame %s', frame.hex(' '))
            return
        LOG.debug('frame %s -> %s', frame.hex(' '),
                  report.get('decoded', report['raw']))
        self.store.mark_dirty()
        self.publish_state()

    # -- seeding ------------------------------------------------------------
    def _seed(self):
        """After (re)connect: catch a dump if one comes, else inquiry only."""
        gen = self.store.generation

        def alive():
            return not self._stop.is_set() and self.store.generation == gen

        dump_wait = float(self.cfg['DUMP_WAIT'])
        seq = self.store.current_seq
        core = lambda r: r.get('type') != 0x30 and r.get('id') in (0x21, 0x26, 0x28)
        LOG.info('seed: waiting up to %.0fs for a connection dump', dump_wait)
        self.store.wait(core, seq, dump_wait, alive=alive)
        if not alive():
            return

        fresh_input = self.store.poll(state_pred(0x21), seq) is not None
        fresh_vol = self.store.poll(state_pred(0x26), seq) is not None
        state = self.store.parser.state
        LOG.info('seed: dump %s (input=%s volume=%s)',
                 'received' if (fresh_input or fresh_vol) else 'NOT received',
                 'fresh' if fresh_input else state['input'],
                 'fresh' if fresh_vol else state['volume'])

        dumped = fresh_input or fresh_vol
        # Volume probing is GONE (2026-10-12): the old "net-zero" probe used
        # vol_down+vol_up, but vol_down (07A1B) is a NO-OP on this receiver —
        # it reports the unchanged current value — while vol_up really steps
        # +0.5 dB. So every restart leaked +0.5 dB (that's how the volume kept
        # creeping up). There is no report-producing read-back for volume
        # ("230" sets are silent, and vol_up is the only live key), so volume
        # state now comes only from the persisted file, user events, and our
        # own silent sets. Do not reintroduce a vol-key probe.
        need_input = (cfg_bool(self.cfg, 'SEED_REFRESH_INPUT')
                      and not fresh_input and state.get('input') is not None)
        if state['power'] is None and dumped:
            state['power'] = True      # dumps only happen while powered on

        if not dumped:
            # No dump — the liveness inquiry decides power and gates probing.
            if not self._inquiry_alive(alive):
                LOG.warning('seed: receiver not responding — assuming standby')
                if state['power'] is None:
                    state['power'] = False
                self.publish_state(force=True)
                self.store.mark_dirty()
                return
            if state['power'] is None:
                state['power'] = True

        if need_input and alive():
            self._refresh_input(alive, state['input'])
        self.publish_state(force=True)
        self.store.mark_dirty()
        LOG.info('seed: complete (power=%s input=%s volume=%s)',
                 state['power'], state['input_name'], state['volume'])

    def _inquiry_alive(self, alive):
        for attempt in range(2):
            if not alive():
                return False
            seq = self.store.current_seq
            try:
                self.link.send(INQUIRY)
            except ConnectionError:
                return False
            if self.store.wait(ack_pred, seq, 1.5, alive=alive):
                return True
        return False

    # (_probe_volume removed 2026-10-12 — see the tombstone in _seed:
    #  vol_down is a no-op on this receiver, so the "net-zero" vol_down+vol_up
    #  probe actually leaked +0.5 dB on every daemon restart.)

    def _refresh_input(self, alive, value):
        """Resend the stored input (redundant -> input + group reports).

        Off by default: if the input changed while the daemon was down this
        would force it back to the stored value.
        """
        record = VALUE_TO_INPUT_RECORD.get(value)
        if record is None:
            return
        seq = self.store.current_seq
        try:
            self.link.send(full(record))
        except ConnectionError:
            return
        rep = self.store.wait(state_pred(0x21), seq, 2.0, alive=alive)
        LOG.info('input refresh: %s -> %s',
                 value, rep['value'] if rep else 'no report')

    # -- command execution --------------------------------------------------
    def build_job(self, field, payload):
        f = field.strip().lower()
        p = payload.strip()

        if f == 'power':
            on = parse_bool(p)
            return {
                'name': 'power ' + ('on' if on else 'off'),
                'frame': CTRL['power_on'] if on else CTRL['power_off'],
                'expect': 0x20, 'timeout': 2.5,
                'retries': 1 if on else 0, 'retry_delay': 1.0,
                'power': True,
            }

        if f == 'input':
            value = INPUT_BY_NORM.get(norm(p))
            if value is None:
                try:
                    value = int(p, 0)
                except ValueError:
                    raise ValueError('unknown input %r' % p)
            record = VALUE_TO_INPUT_RECORD.get(value)
            if record is None:
                raise ValueError('no record for input value %r' % value)
            return {'name': 'input=%s' % INPUT_NAMES.get(value, value),
                    'frame': full(record), 'expect': 0x21, 'timeout': 2.0}

        if f in ('volume_db', 'volume'):
            if f == 'volume_db':
                try:
                    raw = int(round((float(p) + 80.0) * 2))
                except ValueError:
                    raise ValueError('bad dB value %r' % p)
            else:
                try:
                    raw = int(float(p))
                except ValueError:
                    raise ValueError('bad volume %r' % p)
            raw = max(0, min(188, raw))
            wire = raw + VOLUME_WIRE_OFFSET if raw else 0
            return {'name': 'volume=%d (%.1f dB)' % (raw, raw / 2 - 80),
                    'frame': YamahaController.set_volume_frame(raw),
                    'expect': 0x26, 'timeout': 1.5, 'echo_wire': wire,
                    # 2026-10-12: the receiver applies "230" volume sets
                    # SILENTLY — it echoes the wire byte and never sends a
                    # state report (panel-verified: set byte 128 landed at
                    # -35.5 dB with zero reports). So for volume the echo
                    # IS the ack and the value DID change; store the
                    # intended raw ourselves since no report will follow.
                    'echo_applies': raw}

        if f == 'mute':
            on = parse_bool(p)
            return {'name': 'mute ' + ('on' if on else 'off'),
                    'frame': CTRL['mute_on'] if on else CTRL['mute_off'],
                    'expect': 0x23, 'timeout': 1.5}

        if f == 'straight':
            on = parse_bool(p)
            return {'name': 'straight ' + ('on' if on else 'off'),
                    'frame': CTRL['straight_on'] if on else CTRL['straight_off'],
                    'expect': 0x28, 'timeout': 1.5}

        if f == 'speaker_b':
            on = parse_bool(p)
            return {'name': 'speaker B ' + ('on' if on else 'off'),
                    'frame': CTRL['speaker_b_on'] if on else CTRL['speaker_b_off'],
                    'expect': 0x2F, 'timeout': 1.5}

        if f == 'sound_program':
            value = PROGRAM_BY_NORM.get(norm(p))
            if value is None:
                try:
                    value = int(p, 0)
                except ValueError:
                    raise ValueError('unknown sound program %r' % p)
            record = PROGRAM_TO_RECORD.get(value)
            if record is None:
                raise ValueError('no record for program 0x%02X' % value)
            return {'name': 'program=%s' % SOUND_PROGRAM_NAMES.get(value, value),
                    'frame': full(record), 'expect': 0x28, 'timeout': 1.5}

        if f == 'ext_surround':
            record = EXT_TO_RECORD.get(norm(p))
            if record is None:
                raise ValueError('unknown ext surround %r (want %s)'
                                 % (p, '/'.join(sorted(EXT_TO_RECORD))))
            return {'name': 'ext_surround=%s' % p,
                    'frame': full(record), 'expect': 0x2D, 'timeout': 1.5}

        if f == 'sleep':
            record = SLEEP_TO_RECORD.get(norm(p))
            if record is None:
                raise ValueError('unknown sleep %r (want OFF/30min/...)' % p)
            return {'name': 'sleep=%s' % p,
                    'frame': full(record), 'expect': 0x2C, 'timeout': 1.5}

        if f == 'night_mode':
            record = NIGHT_TO_RECORD.get(norm(p))
            if record is None:
                raise ValueError('unknown night mode %r (want %s)'
                                 % (p, '/'.join(sorted(NIGHT_TO_RECORD))))
            return {'name': 'night_mode=%s' % p,
                    'frame': full(record), 'expect': 0x82, 'timeout': 1.5}

        raise ValueError('unknown field %r' % field)

    def _worker(self):
        while not self._stop.is_set():
            try:
                job = self.jobs.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._run_job(job)
            except Exception:
                LOG.exception('command %s crashed', job.get('name'))

    def _run_job(self, job):
        expect = job['expect']
        pred = state_pred(expect)
        retries = job.get('retries', 0)
        echo = (echo_pred(expect, job['echo_wire'])
                if job.get('echo_wire') is not None else None)

        for attempt in range(1 + retries):
            seq = self.store.current_seq
            try:
                self.link.send(job['frame'])
            except ConnectionError as exc:
                LOG.warning('%s not sent: %s', job['name'], exc)
                return
            rep = self.store.wait(pred, seq, job['timeout'])
            if rep is not None:
                LOG.info('%s acked: %s', job['name'],
                         rep.get('decoded', rep['raw']))
                return
            if echo is not None and self.store.poll(echo, seq):
                applied = job.get('echo_applies')
                if applied is not None:
                    # "230" volume sets are applied silently: the echo is the
                    # ack and the value DID change — no report will follow, so
                    # record the intended raw in our own state.
                    LOG.info('%s acked by echo (applied silently, no report '
                             'for volume sets)', job['name'])
                    with self.store.lock:
                        self.store.parser.state['volume'] = applied
                        self.store.parser.state['volume_db'] = \
                            applied / 2.0 - 80.0
                    self.store.mark_dirty()
                    self.publish_state()
                else:
                    # Echo only, no state report: value unchanged (delta
                    # reporting), so receiver state already matches.
                    LOG.info('%s acked by echo (value unchanged)', job['name'])
                return
            if attempt < retries:
                LOG.info('%s: no report, retrying in %.1fs',
                         job['name'], job.get('retry_delay', 1.0))
                if self._stop.wait(job.get('retry_delay', 1.0)):
                    return

        LOG.warning('%s: no state report within %.1fs', job['name'],
                    job['timeout'] * (1 + retries))
        if job.get('power'):
            self._resolve_power_after_timeout()

    def _resolve_power_after_timeout(self):
        """Power job got no report — an inquiry ACK proves the receiver is on."""
        if self._stop.wait(0.5):
            return
        alive = lambda: not self._stop.is_set()
        on = self._inquiry_alive(alive)
        with self.store.lock:
            self.store.parser.state['power'] = on
        LOG.info('power resolved via inquiry: %s',
                 'on' if on else 'standby/no answer')
        self.publish_state(force=True)
        self.store.mark_dirty()

    # -- shutdown -----------------------------------------------------------
    def stop(self):
        LOG.info('shutting down')
        self._stop.set()
        self.link.stop()
        try:
            self.mqtt_client.publish(f'{self.root}/availability', 'offline',
                                     qos=1, retain=True)
            self.mqtt_client.publish(f'{self.root}/link', 'OFF', retain=True)
            time.sleep(0.3)
        except Exception:
            pass
        self.mqtt_client.loop_stop()
        try:
            self.mqtt_client.disconnect()
        except Exception:
            pass
        self.store.stop()
        LOG.info('bye')


def main():
    ap = argparse.ArgumentParser(description='RX-V2500 RS-232 -> MQTT daemon')
    ap.add_argument('--config', default='/etc/rxv2500d.conf',
                    help='KEY=VALUE config file (optional)')
    ap.add_argument('--state-file', default=None, help='override STATE_FILE')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.state_file:
        cfg['STATE_FILE'] = args.state_file
    logging.basicConfig(
        level=logging.DEBUG if args.verbose
        else getattr(logging, cfg['LOG_LEVEL'].upper(), logging.INFO),
        format='%(asctime)s %(levelname)-7s %(name)s: %(message)s')

    daemon = Daemon(cfg)

    def shutdown(signum, frame):
        LOG.info('signal %s', signal.Signals(signum).name)
        threading.Thread(target=daemon.stop, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    daemon.start()
    while not daemon._stop.is_set():
        time.sleep(0.5)
    time.sleep(1.0)          # let the shutdown thread finish


if __name__ == '__main__':
    main()
