#!/usr/bin/env python3
"""
Yamaha RX-V2500 RS-232 Control Script
Controls the receiver via ser2net bridge using the RS-232 protocol.

Protocol: Two frame formats discovered via reverse engineering:

1. Full Record: STX (0x02) + 5 ASCII chars + ETX (0x03)
   Example: Power On = b'\x0207A1D\x03'

2. Prefix + Value: STX (0x02) + 3 ASCII chars + 2 hex chars + ETX (0x03)
   Example: Volume = b'\x020230XX\x03' where XX is the hex value

3. Special ID 0xff: 0x11 '0' '0' '0' 0x03
   Example: b'\x11000\x03'

The prefix+value format is used for commands that take a numeric parameter
(volume, tone, balance, etc.) where the value is formatted as two uppercase
hexadecimal characters.
"""

import socket
import time
import sys
import json
import os
from typing import Optional, Union, Dict, Any


VOLUME_WIRE_OFFSET = 0x27
"""Volume wire offset, panel-verified 2026-10-12.

Both the "230" absolute-volume SET and volume REPORTS use
byte = raw + VOLUME_WIRE_OFFSET (raw = half-dB above -80.0).
Ground truth, settled by reading the front panel against controlled
frames: set byte 128 landed at -35.5 dB (raw 89 = 128 - 39); report
byte 169 read back as the panel's -15.0 dB (raw 130 = 169 - 39);
set byte 168 landed at -15.5 dB (raw 129 = 168 - 39).

The value recovered from the RE'd Windows app (0x26) is off by one —
that single wrong constant caused the entire "wire vs raw" confusion
during Phase B (state read +19 dB too high, probes appeared to leak).
"""


def build_prefix_value_command(prefix: str, value: int, adjust_wire: bool = False) -> bytes:
    """
    Build a prefix+value RS-232 command frame.

    Format: STX + 3 ASCII prefix chars + 2 hex chars + ETX

    Args:
        prefix: 3-character ASCII prefix (e.g., "230" for volume)
        value: Integer value to format as two hex chars
        adjust_wire: If True and value != 0, add VOLUME_WIRE_OFFSET before
                     formatting (matches handler 0x42a4fd behavior)

    Returns:
        Complete command frame as bytes

    Example:
        >>> build_prefix_value_command("230", 0)
        b'\\x02023000\\x03'
        >>> build_prefix_value_command("230", 1, adjust_wire=True)
        b'\\x02023028\\x03'
    """
    if adjust_wire and value != 0:
        value += VOLUME_WIRE_OFFSET

    # Format as two uppercase hex digits
    hex_str = f"{value:02X}"

    # Build frame: STX + prefix + hex + ETX
    frame = f"\x02{prefix}{hex_str}\x03"
    return frame.encode('ascii')


def build_full_record_command(record: str) -> bytes:
    """
    Build a full-record RS-232 command frame.

    Format: STX + 5 ASCII record chars + ETX

    Args:
        record: 5-character ASCII record string (e.g., "07A1D")

    Returns:
        Complete command frame as bytes

    Example:
        >>> build_full_record_command("07A1D")
        b'\x0207A1D\x03'
    """
    if len(record) != 5:
        raise ValueError(f"Record must be exactly 5 characters, got {len(record)}: {record}")

    frame = f"\x02{record}\x03"
    return frame.encode('ascii')


# =============================================================================
# Report Parser — decodes unsolicited status reports from the receiver
# =============================================================================

# Input names indexed by report value (Pure Direct OFF).
#
# The receiver uses values 0x00-0x0C but skips 0x08 and 0x0B, so there are
# only 11 distinct values — exactly matching the 11-entry name table found in
# YamahaReceiverEditor3.exe at VMA 0x459524 (15-byte records, indexed 0-10):
#     PHONO, CD, TUNER, CD-R, MD/TAPE, DVD, DTV, CBL/SAT, VCR1, DVR/VCR2, V-AUX
# Removing the two gaps from 0x00-0x0C yields that order.  Endpoints are
# confirmed empirically (07A14 -> 0 = PHONO, 07A55 -> 0x0C = V-AUX); the middle
# is the natural gap-removal mapping and still needs a front-panel eyeball check.
#
# Bit 4 (0x10) indicates Pure Direct is on and must be masked off.
INPUT_NAMES = {
    0x00: 'PHONO',
    0x01: 'CD',
    0x02: 'TUNER',
    0x03: 'CD-R',
    0x04: 'MD/TAPE',
    0x05: 'DVD',
    0x06: 'DTV',
    0x07: 'CBL/SAT',
    0x09: 'VCR1',
    0x0A: 'DVR/VCR2',
    0x0C: 'V-AUX',
}

# Input-select command records (command-table ID 0x02, 13 records) and the
# input value each one provokes.  Two pairs are aliases: 07AC0/07ACA both
# select 0x07 and 07A13/07AC8 both select 0x0A.  07EA0 (ID 0x06, "multi-ch")
# also reported 0x0A.
INPUT_RECORDS = {
    '07A14': 0x00, '07A15': 0x01, '07A16': 0x02, '07A19': 0x03,
    '07AC9': 0x04, '07AC1': 0x05, '07A54': 0x06, '07AC0': 0x07,
    '07ACA': 0x07, '07A0F': 0x09, '07A13': 0x0A, '07AC8': 0x0A,
    '07A55': 0x0C,
}

# Sound program values for field ID 0x28 (bottom 7 bits).
#
# Bit 7 (0x80) is the STRAIGHT flag: with STRAIGHT active the receiver reports
# 0x80 | <last selected program>, e.g. STRAIGHT over Spectacle reports 0xA4.
# Verified: Munich(0)->0x80, Vienna(5)->0x85, Bottom Line(0x0E)->0x8E,
# Roxy(0x10)->0x90, 7ch Stereo(0x17)->0x97, TV Sports(0x21)->0xA1,
# Sci-Fi(0x25)->0xA5, Spectacle(0x24)->0xA4, 2ch Stereo(0x34)->0xB4,
# THX Cinema(0x36)->0xB6.
SOUND_PROGRAM_NAMES = {
    0x00: 'HALL_MUNICH',
    0x05: 'HALL_VIENNA',
    0x09: 'HALL_FREIBURG',
    0x0E: 'HALL_BOTTOM_LINE',
    0x10: 'HALL_ROXY',
    0x14: 'DISCO',
    0x16: 'GAME',
    0x17: 'STEREO_7CH',
    0x18: 'POP_ROCK',
    0x1C: 'CLASSICAL',
    0x20: 'MONO_MOVIE',
    0x21: 'TV_SPORTS',
    0x24: 'SPECTACLE',
    0x25: 'SCI_FI',
    0x28: 'ADVENTURE',
    0x29: 'GENERAL',
    0x2C: 'PRO_LOGIC',
    0x2D: 'PRO_LOGIC_ENHANCED',
    0x34: 'STEREO_2CH',
    0x36: 'THX_CINEMA',
}
SOUND_PROGRAM_STRAIGHT_BIT = 0x80

# Extended surround (field ID 0x2D).  Values depend on the active program, so
# these are the observed command->value pairs rather than a fixed enum.
EXT_SURROUND_NAMES = {
    0x00: 'OFF',
    0x01: 'ES/EX',
    0x03: 'AUTO',
    0x05: 'PLIIx_MOVIE',
    0x06: 'PLIIx_MUSIC',
}

# Sleep timer (field ID 0x2C)
SLEEP_NAMES = {
    0x00: '120min',
    0x01: '90min',
    0x02: '60min',
    0x03: '30min',
    0x04: 'OFF',
}

# Night mode (field ID 0x82)
NIGHT_MODE_NAMES = {
    0x00: 'OFF',
    0x02: 'CINEMA_MID',
    0x05: 'MUSIC_MID',
}


def decode_sound_mode(value: int) -> Dict[str, Any]:
    """Decode a field 0x28 value into {'straight': bool, 'program': str}."""
    straight = bool(value & SOUND_PROGRAM_STRAIGHT_BIT)
    program = value & ~SOUND_PROGRAM_STRAIGHT_BIT
    return {
        'straight': straight,
        'program_id': program,
        'program': SOUND_PROGRAM_NAMES.get(program, f'UNKNOWN(0x{program:02X})'),
    }


def sound_mode_name(value: int) -> str:
    """Human-readable sound mode for a field 0x28 value."""
    d = decode_sound_mode(value)
    return f"STRAIGHT+{d['program']}" if d['straight'] else d['program']


def input_name(value: int) -> str:
    """
    Return the input name for a field 0x21 value.

    Bit 4 (0x10) indicates Pure Direct is on and is masked off.
    """
    return INPUT_NAMES.get(value & ~0x10, f'UNKNOWN(0x{value:02X})')

# Report type constants.  The type byte is a *category*, not a discriminator:
# the same field ID shows up under several types (e.g. id 0x28 appears as
# 0x00, 0x01 and 0x10; id 0x22 as 0x00 and 0x01).  Decoding is therefore keyed
# on the field ID, with the type retained for diagnostics.
REPORT_SETTING = 0x00
REPORT_SOUND_MODE = 0x01
REPORT_NIGHT_MODE = 0x02
REPORT_MAIN_ZONE = 0x10   # main-zone setting change (volume, input, mode, ...)
REPORT_PURE_DIRECT = 0x20 # pure direct state change (id 0x8C)
REPORT_GROUP = 0x30       # group status / ACK

# Known report field IDs
REPORT_ID_POWER = 0x20         # power state: 0=standby, 2=on (0x00 type)
REPORT_ID_POWER_B = 0xB0       # companion power flag: 0=standby (seen on power-off)
REPORT_ID_INPUT = 0x21        # 0x00-0x0C, gaps at 0x08 and 0x0B
REPORT_ID_UNKNOWN_22 = 0x22   # stable per-input attribute; observed 0x00/0x02/0x05
REPORT_ID_MUTE = 0x23         # 0=off, 1=on
REPORT_ID_VOLUME = 0x26       # dB = value/2 - 80
REPORT_ID_SOUND_MODE = 0x28   # program value; bit 0x80 = STRAIGHT
REPORT_ID_SLEEP = 0x2C        # 0=120min 1=90min 2=60min 3=30min 4=off
REPORT_ID_EXT_SURROUND = 0x2D # extended surround setting
REPORT_ID_SPEAKER_B = 0x2F    # 0=off, 1=on
REPORT_ID_NIGHT_MODE = 0x82   # 0=off, 2=cinema, 5=music
REPORT_ID_PURE_DIRECT = 0x8C  # 0=off, 1=on (usually type 0x20)

# Group status IDs (type=0x30)
GROUP_IDS = {0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x36, 0x3C}

# Observed ACK: query-page inquiries answer with 30 00 00 (group 0x00 = 0),
# so there is no polling/status-dump command — only the connection-open dump.
ACK_FRAME = bytes.fromhex('0233303030303003')


class ReportParser:
    """Parse RS-232 status reports and maintain receiver state."""

    def __init__(self):
        self.state: Dict[str, Any] = {
            'power': None,
            'input': None,
            'input_name': None,
            'input_pure_direct': None,
            'volume': None,
            'volume_db': None,
            'mute': None,
            'sound_mode': None,
            'sound_program': None,
            'straight': None,
            'sleep': None,
            'night_mode': None,
            'ext_surround': None,
            'speaker_b': None,
            'pure_direct': None,
        }
        self.raw_log: list = []

    def parse_frame(self, frame: bytes) -> Optional[Dict[str, Any]]:
        """
        Parse a report frame.

        Format: STX + type(1B) + id(1B) + value(1B) + ETX (8 bytes total)

        Returns dict with decoded fields, or None if not a valid report.
        """
        if len(frame) < 2:
            return None

        payload = frame[1:-1]  # strip STX and ETX

        # Reports have 6 hex chars (3 bytes)
        if len(payload) != 6:
            return None

        try:
            b0 = int(payload[0:2], 16)
            b1 = int(payload[2:4], 16)
            b2 = int(payload[4:6], 16)
        except ValueError:
            return None

        report = {
            'raw': frame.hex(' '),
            'type': b0,
            'id': b1,
            'value': b2,
        }

        self.raw_log.append(report)

        # Group status (type 0x30) is its own namespace. It also doubles as
        # the COMMAND ECHO: after a set command the receiver answers with
        # type=0x30 echoing the WIRE byte (e.g. volume set "230 CF" ->
        # "30 26 CF", where 0xCF = raw + VOLUME_WIRE_OFFSET, NOT the raw
        # volume). Never treat type=0x30 as state.
        if b0 == REPORT_GROUP:
            self._decode_group(b1, b2, report)
            return report

        # Everything else is decoded by field ID — the type byte is only a
        # category and does not change the meaning of the value.
        if b1 == REPORT_ID_PURE_DIRECT:
            self.state['pure_direct'] = bool(b2)
            report['decoded'] = f"pure_direct={'on' if b2 else 'off'}"
        else:
            self._decode_field(b1, b2, report)

        return report

    def _decode_field(self, field_id: int, value: int, report: Dict):
        """Decode a report by field ID (type-independent)."""
        if field_id == REPORT_ID_POWER:
            self.state['power'] = bool(value)
            report['decoded'] = f"power={'on' if value else 'standby'} (0x{value:02X})"
        elif field_id == REPORT_ID_POWER_B:
            report['decoded'] = f"power_flag(0xB0)=0x{value:02X}"
        elif field_id == REPORT_ID_INPUT:
            self.state['input'] = value
            self.state['input_pure_direct'] = bool(value & 0x10)
            self.state['input_name'] = input_name(value)
            report['decoded'] = f"input={self.state['input_name']} (0x{value:02X})"
        elif field_id == REPORT_ID_MUTE:
            self.state['mute'] = bool(value)
            report['decoded'] = f"mute={'on' if value else 'off'}"
        elif field_id == REPORT_ID_VOLUME:
            # Volume reports carry the WIRE byte (raw + VOLUME_WIRE_OFFSET
            # = 0x27) — the same encoding as the "230" set command — NOT
            # the raw value. Ground-truthed against the front panel on
            # 2026-10-12: report byte 169 <-> panel -15.0 dB (raw 130);
            # report byte 121 <-> panel -39.0 dB (raw 82, after one
            # vol-up step from raw 81). The old decode (value/2-80, and
            # briefly value-0x26) read wrong by +19/+19.5 dB.
            raw = max(0, value - VOLUME_WIRE_OFFSET) if value else 0
            self.state['volume'] = raw
            self.state['volume_db'] = (raw / 2.0) - 80.0
            report['decoded'] = ('volume wire=%d raw=%d (%.1f dB)'
                                 % (value, raw, self.state['volume_db']))
        elif field_id == REPORT_ID_SOUND_MODE:
            self.state['sound_mode'] = value
            decoded = decode_sound_mode(value)
            self.state['straight'] = decoded['straight']
            self.state['sound_program'] = decoded['program']
            report['decoded'] = f"sound_mode={sound_mode_name(value)} (0x{value:02X})"
        elif field_id == REPORT_ID_SLEEP:
            self.state['sleep'] = value
            report['decoded'] = f"sleep={SLEEP_NAMES.get(value, f'0x{value:02X}')}"
        elif field_id == REPORT_ID_EXT_SURROUND:
            self.state['ext_surround'] = value
            name = EXT_SURROUND_NAMES.get(value, f'0x{value:02X}')
            report['decoded'] = f"ext_surround={name}"
        elif field_id == REPORT_ID_SPEAKER_B:
            self.state['speaker_b'] = bool(value)
            report['decoded'] = f"speaker_B={'on' if value else 'off'}"
        elif field_id == REPORT_ID_NIGHT_MODE:
            self.state['night_mode'] = value
            report['decoded'] = f"night_mode={NIGHT_MODE_NAMES.get(value, f'0x{value:02X}')}"
        elif field_id == REPORT_ID_UNKNOWN_22:
            report['decoded'] = f"input_attr(0x22)={value}"
        else:
            report['decoded'] = f"id=0x{field_id:02X} val=0x{value:02X}"

    def _decode_group(self, field_id: int, value: int, report: Dict):
        """Decode a type=0x30 group status report (or command echo)."""
        # Command echo: after a set command, type=0x30 echoes the WIRE byte.
        # For volume ("230" prefix) the wire byte is raw + VOLUME_WIRE_OFFSET
        # — do NOT confuse it with the state report (type 0x00/0x10, id 0x26).
        if field_id == REPORT_ID_VOLUME:
            report['decoded'] = ('echo volume wire=0x%02X (raw ~%d)'
                                 % (value, value - VOLUME_WIRE_OFFSET))
            report['is_echo'] = True
            return
        if field_id == 0x00:
            # 30 00 00 is the ACK for inquiry frames; 30 00 01 seen in the
            # connection-open dump.
            report['decoded'] = f"group[0x00]={value} ({'ACK' if value == 0 else 'set'})"
        elif field_id in (0x10, 0x11):
            report['decoded'] = f"speakers[0x{field_id:02X}]=0x{value:02X}"
        else:
            report['decoded'] = f"group[0x{field_id:02X}]=0x{value:02X}"

    def get_status(self) -> Dict[str, Any]:
        """Return current receiver state."""
        return dict(self.state)

    def get_status_json(self) -> str:
        """Return current receiver state as JSON."""
        return json.dumps(self.state, indent=2)


class YamahaController:
    """Controller for Yamaha RX-V2500 via RS-232/ser2net or direct TCP"""

    # Protocol modes
    PROTOCOL_RS232 = 'rs232'  # Via ser2net (port 3333) - simple 7-byte packets
    PROTOCOL_DIP = 'dip'      # Direct TCP (port 2500) - requires handshake

    # DIP Protocol handshake commands (for port 2500)
    HANDSHAKE_INIT = b'\x14210503\x03'
    HANDSHAKE_SYSTEM_QUERY = b'\x1420090200000020\x3A\x03'

    # RS-232 Command definitions - CONFIRMED WORKING on RX-V2500
    COMMANDS_RS232 = {
        # Power (ID 0x00, full record)
        'power_on': b'\x0207A1D\x03',
        'power_off': b'\x0207A1E\x03',

        # Volume (ID 0x00, full record - auto-repeat enabled for command-line)
        'vol_up': b'\x0207A1A\x03',
        'vol_down': b'\x0207A1B\x03',
        'mute_on': b'\x0207EA2\x03',
        'mute_off': b'\x0207EA3\x03',

        # Volume Memory (ID 0x11, full record)
        'vol_memory_6': b'\x0207E70\x03',

        # Input Selection (ID 0x02, full record) — see the full list further
        # down for the complete record->value mapping.
        'input_multi': b'\x0207EA0\x03',  # ID 0x06; reports 0x0A (DVR/VCR2)
        'input_vcr1': b'\x0207A0F\x03',   # reports 0x09 VCR1
        'input_dtv': b'\x0207A54\x03',    # reports 0x06 DTV
        'input_vaux': b'\x0207A55\x03',   # reports 0x0C V-AUX

        # Speakers (ID 0x03, full record) - CORRECTED: B codes were swapped
        'speaker_a_on': b'\x0207EA7\x03',   # Shows input name/mode
        'speaker_a_off': b'\x0207EA8\x03',  # May affect input mode
        'speaker_b_on': b'\x0207EAD\x03',   # Was labeled "off" - CORRECTED
        'speaker_b_off': b'\x0207EAE\x03',  # Was labeled "on" - CORRECTED

        # Sleep Timer (ID 0x04, full record)
        'sleep_off': b'\x0207EB3\x03',
        'sleep_30min': b'\x0207EB7\x03',
        'sleep_60min': b'\x0207EB6\x03',
        'sleep_90min': b'\x0207EB5\x03',
        'sleep_120min': b'\x0207EB4\x03',

        # Night Mode (ID 0x05, full record)
        'night_off': b'\x0207E9C\x03',
        'night_cinema_mid': b'\x0207E9B\x03',
        'night_music_mid': b'\x0207ECF\x03',

        # Sound Modes - Basic (ID 0x06, full record)
        # STRAIGHT is an on/off PAIR (table id 0x13 = 07EE0|07E27), live-
        # verified: program under bit 0x80 is preserved across toggles.
        # straight_on/straight_off defined with the ID-0x13 group below.
        'pure_direct_on': b'\x0207E80\x03',  # ON only, not toggle
        'straight': b'\x0207EE0\x03',        # STRAIGHT on (alias of straight_on)

        # Sound Modes - Stereo (ID 0x06, full record)
        'stereo_2ch': b'\x0207EC0\x03',
        'stereo_7ch': b'\x0207EFF\x03',

        # Sound Modes - THX (ID 0x06, full record)
        'thx_cinema': b'\x0207EC2\x03',

        # Surround Modes - Standard (ID 0x06, full record)
        'surround_pro_logic': b'\x0207EFD\x03',
        'surround_pro_logic_enhanced': b'\x0207EFE\x03',

        # Surround Modes - Extended (ID 0x07, full record)
        'ext_surround_auto': b'\x0207E7C\x03',
        'ext_surround_es_ex': b'\x0207E7D\x03',
        'ext_surround_off': b'\x0207EB9\x03',
        'ext_surround_pliix_movie': b'\x0207EDD\x03',
        'ext_surround_pliix_music': b'\x0207EDE\x03',

        # Sound Modes - Music Hall (ID 0x13, full record)
        'music_hall_munich': b'\x0207EE1\x03',
        'music_hall_vienna': b'\x0207EE5\x03',
        'music_hall_freiburg': b'\x0207EE8\x03',
        'music_hall_bottom_line': b'\x0207EEC\x03',
        'music_hall_roxy': b'\x0207EED\x03',

        # Sound Modes - Entertainment (ID 0x14, full record)
        'entertainment_disco': b'\x0207EF0\x03',
        'entertainment_game': b'\x0207EF2\x03',
        'entertainment_mono_movie': b'\x0207EF7\x03',
        'entertainment_tv_sports': b'\x0207EF8\x03',
        'entertainment_toggle': b'\x0207A8A\x03',  # Cycles: TV Sport → Mono Movie → Game → Disco

        # Sound Modes - Music (ID 0x14, full record)
        'music_pop_rock': b'\x0207EF3\x03',
        'music_classical': b'\x0207EF5\x03',

        # Sound Modes - Movie Theater (ID 0x14, full record)
        'movie_spectacle': b'\x0207EF9\x03',
        'movie_sci_fi': b'\x0207EFA\x03',
        'movie_adventure': b'\x0207EFB\x03',
        'movie_general': b'\x0207EFC\x03',

        # DC Trigger - Main (ID 0x15, full record)
        'dc_trigger_high': b'\x0207E73\x03',
        'dc_trigger_low': b'\x0207E74\x03',

        # DC Trigger - Multi-Zone (ID 0x15, full record)
        'dc_trigger_2_zone1': b'\x0207E96\x03',
        'dc_trigger_2_zone2': b'\x0207E97\x03',
        'dc_trigger_2_zone3': b'\x0207E9F\x03',

        # === NEW: Prefix + Value Commands (discovered via reverse engineering) ===
        # These use the format: STX + 3 ASCII prefix + 2 hex chars + ETX
        # The value is formatted as two uppercase hexadecimal digits

        # Volume Level (ID 0x30, prefix "230", Handler A with +0x27 adjustment (VOLUME_WIRE_OFFSET, panel-verified 2026-10-12)
        # Value 0 = hex "00", Value 1 = hex "28" (0x01 + 0x27), etc.
        'vol_level_0': build_prefix_value_command("230", 0, adjust_wire=True),
        'vol_level_1': build_prefix_value_command("230", 1, adjust_wire=True),
        'vol_level_2': build_prefix_value_command("230", 2, adjust_wire=True),
        'vol_level_3': build_prefix_value_command("230", 3, adjust_wire=True),
        'vol_level_4': build_prefix_value_command("230", 4, adjust_wire=True),
        'vol_level_5': build_prefix_value_command("230", 5, adjust_wire=True),
        'vol_level_6': build_prefix_value_command("230", 6, adjust_wire=True),
        'vol_level_7': build_prefix_value_command("230", 7, adjust_wire=True),
        'vol_level_8': build_prefix_value_command("230", 8, adjust_wire=True),
        'vol_level_9': build_prefix_value_command("230", 9, adjust_wire=True),
        'vol_level_10': build_prefix_value_command("230", 10, adjust_wire=True),

        # Zone 2 Volume (ID 0x31, prefix "231", Handler A with +0x27 adjustment (VOLUME_WIRE_OFFSET, panel-verified 2026-10-12)
        'zone2_vol_0': build_prefix_value_command("231", 0, adjust_wire=True),
        'zone2_vol_1': build_prefix_value_command("231", 1, adjust_wire=True),
        'zone2_vol_2': build_prefix_value_command("231", 2, adjust_wire=True),
        'zone2_vol_3': build_prefix_value_command("231", 3, adjust_wire=True),
        'zone2_vol_4': build_prefix_value_command("231", 4, adjust_wire=True),
        'zone2_vol_5': build_prefix_value_command("231", 5, adjust_wire=True),

        # Zone 3 Volume (ID 0x32, prefix "232", Handler B - direct hex)
        'zone3_vol_0': build_prefix_value_command("232", 0),
        'zone3_vol_1': build_prefix_value_command("232", 1),
        'zone3_vol_2': build_prefix_value_command("232", 2),
        'zone3_vol_3': build_prefix_value_command("232", 3),
        'zone3_vol_4': build_prefix_value_command("232", 4),
        'zone3_vol_5': build_prefix_value_command("232", 5),

        # Zone 4 Volume (ID 0x34, prefix "234", Handler A with +0x27 adjustment (VOLUME_WIRE_OFFSET, panel-verified 2026-10-12)
        'zone4_vol_0': build_prefix_value_command("234", 0, adjust_wire=True),
        'zone4_vol_1': build_prefix_value_command("234", 1, adjust_wire=True),
        'zone4_vol_2': build_prefix_value_command("234", 2, adjust_wire=True),
        'zone4_vol_3': build_prefix_value_command("234", 3, adjust_wire=True),
        'zone4_vol_4': build_prefix_value_command("234", 4, adjust_wire=True),
        'zone4_vol_5': build_prefix_value_command("234", 5, adjust_wire=True),

        # Tone Control - Bass (ID 0x36, prefix "240", Handler B - direct hex)
        'bass_0': build_prefix_value_command("240", 0),
        'bass_1': build_prefix_value_command("240", 1),
        'bass_2': build_prefix_value_command("240", 2),
        'bass_3': build_prefix_value_command("240", 3),
        'bass_4': build_prefix_value_command("240", 4),
        'bass_5': build_prefix_value_command("240", 5),
        'bass_6': build_prefix_value_command("240", 6),
        'bass_7': build_prefix_value_command("240", 7),
        'bass_8': build_prefix_value_command("240", 8),
        'bass_9': build_prefix_value_command("240", 9),
        'bass_10': build_prefix_value_command("240", 10),

        # Tone Control - Treble (ID 0x37, prefix "241", Handler B - direct hex)
        'treble_0': build_prefix_value_command("241", 0),
        'treble_1': build_prefix_value_command("241", 1),
        'treble_2': build_prefix_value_command("241", 2),
        'treble_3': build_prefix_value_command("241", 3),
        'treble_4': build_prefix_value_command("241", 4),
        'treble_5': build_prefix_value_command("241", 5),
        'treble_6': build_prefix_value_command("241", 6),
        'treble_7': build_prefix_value_command("241", 7),
        'treble_8': build_prefix_value_command("241", 8),
        'treble_9': build_prefix_value_command("241", 9),
        'treble_10': build_prefix_value_command("241", 10),

        # Balance (ID 0x38, prefix "242", Handler B - direct hex)
        'balance_0': build_prefix_value_command("242", 0),
        'balance_1': build_prefix_value_command("242", 1),
        'balance_2': build_prefix_value_command("242", 2),
        'balance_3': build_prefix_value_command("242", 3),
        'balance_4': build_prefix_value_command("242", 4),
        'balance_5': build_prefix_value_command("242", 5),
        'balance_6': build_prefix_value_command("242", 6),
        'balance_7': build_prefix_value_command("242", 7),
        'balance_8': build_prefix_value_command("242", 8),
        'balance_9': build_prefix_value_command("242", 9),
        'balance_10': build_prefix_value_command("242", 10),

        # Loudness (ID 0x39, prefix "243", Handler B - direct hex)
        'loudness_0': build_prefix_value_command("243", 0),
        'loudness_1': build_prefix_value_command("243", 1),
        'loudness_2': build_prefix_value_command("243", 2),
        'loudness_3': build_prefix_value_command("243", 3),
        'loudness_4': build_prefix_value_command("243", 4),
        'loudness_5': build_prefix_value_command("243", 5),
        'loudness_6': build_prefix_value_command("243", 6),
        'loudness_7': build_prefix_value_command("243", 7),
        'loudness_8': build_prefix_value_command("243", 8),
        'loudness_9': build_prefix_value_command("243", 9),
        'loudness_10': build_prefix_value_command("243", 10),

        # Effect Level (ID 0x3a, prefix "244", Handler B - direct hex)
        'effect_0': build_prefix_value_command("244", 0),
        'effect_1': build_prefix_value_command("244", 1),
        'effect_2': build_prefix_value_command("244", 2),
        'effect_3': build_prefix_value_command("244", 3),
        'effect_4': build_prefix_value_command("244", 4),
        'effect_5': build_prefix_value_command("244", 5),
        'effect_6': build_prefix_value_command("244", 6),
        'effect_7': build_prefix_value_command("244", 7),
        'effect_8': build_prefix_value_command("244", 8),
        'effect_9': build_prefix_value_command("244", 9),
        'effect_10': build_prefix_value_command("244", 10),

        # Dialog Level (ID 0x3b, prefix "245", Handler B - direct hex)
        'dialog_0': build_prefix_value_command("245", 0),
        'dialog_1': build_prefix_value_command("245", 1),
        'dialog_2': build_prefix_value_command("245", 2),
        'dialog_3': build_prefix_value_command("245", 3),
        'dialog_4': build_prefix_value_command("245", 4),
        'dialog_5': build_prefix_value_command("245", 5),
        'dialog_6': build_prefix_value_command("245", 6),
        'dialog_7': build_prefix_value_command("245", 7),
        'dialog_8': build_prefix_value_command("245", 8),
        'dialog_9': build_prefix_value_command("245", 9),
        'dialog_10': build_prefix_value_command("245", 10),

        # Dialogue Lift (ID 0x3c, prefix "246", Handler B - direct hex)
        'dialog_lift_0': build_prefix_value_command("246", 0),
        'dialog_lift_1': build_prefix_value_command("246", 1),
        'dialog_lift_2': build_prefix_value_command("246", 2),
        'dialog_lift_3': build_prefix_value_command("246", 3),
        'dialog_lift_4': build_prefix_value_command("246", 4),
        'dialog_lift_5': build_prefix_value_command("246", 5),
        'dialog_lift_6': build_prefix_value_command("246", 6),
        'dialog_lift_7': build_prefix_value_command("246", 7),
        'dialog_lift_8': build_prefix_value_command("246", 8),
        'dialog_lift_9': build_prefix_value_command("246", 9),
        'dialog_lift_10': build_prefix_value_command("246", 10),

        # Subwoofer Level (ID 0x3d, prefix "247", Handler B - direct hex)
        'subwoofer_0': build_prefix_value_command("247", 0),
        'subwoofer_1': build_prefix_value_command("247", 1),
        'subwoofer_2': build_prefix_value_command("247", 2),
        'subwoofer_3': build_prefix_value_command("247", 3),
        'subwoofer_4': build_prefix_value_command("247", 4),
        'subwoofer_5': build_prefix_value_command("247", 5),
        'subwoofer_6': build_prefix_value_command("247", 6),
        'subwoofer_7': build_prefix_value_command("247", 7),
        'subwoofer_8': build_prefix_value_command("247", 8),
        'subwoofer_9': build_prefix_value_command("247", 9),
        'subwoofer_10': build_prefix_value_command("247", 10),

        # Presence Level (ID 0x3e, prefix "248", Handler B - direct hex)
        'presence_0': build_prefix_value_command("248", 0),
        'presence_1': build_prefix_value_command("248", 1),
        'presence_2': build_prefix_value_command("248", 2),
        'presence_3': build_prefix_value_command("248", 3),
        'presence_4': build_prefix_value_command("248", 4),
        'presence_5': build_prefix_value_command("248", 5),
        'presence_6': build_prefix_value_command("248", 6),
        'presence_7': build_prefix_value_command("248", 7),
        'presence_8': build_prefix_value_command("248", 8),
        'presence_9': build_prefix_value_command("248", 9),
        'presence_10': build_prefix_value_command("248", 10),

        # Sleeper (ID 0x3f, prefix "249", Handler B - direct hex)
        'sleeper_0': build_prefix_value_command("249", 0),
        'sleeper_1': build_prefix_value_command("249", 1),
        'sleeper_2': build_prefix_value_command("249", 2),
        'sleeper_3': build_prefix_value_command("249", 3),
        'sleeper_4': build_prefix_value_command("249", 4),
        'sleeper_5': build_prefix_value_command("249", 5),
        'sleeper_6': build_prefix_value_command("249", 6),
        'sleeper_7': build_prefix_value_command("249", 7),
        'sleeper_8': build_prefix_value_command("249", 8),
        'sleeper_9': build_prefix_value_command("249", 9),
        'sleeper_10': build_prefix_value_command("249", 10),

        # Program (ID 0x40, prefix "24A", Handler B - direct hex)
        'program_0': build_prefix_value_command("24A", 0),
        'program_1': build_prefix_value_command("24A", 1),
        'program_2': build_prefix_value_command("24A", 2),
        'program_3': build_prefix_value_command("24A", 3),
        'program_4': build_prefix_value_command("24A", 4),
        'program_5': build_prefix_value_command("24A", 5),
        'program_6': build_prefix_value_command("24A", 6),
        'program_7': build_prefix_value_command("24A", 7),
        'program_8': build_prefix_value_command("24A", 8),
        'program_9': build_prefix_value_command("24A", 9),
        'program_10': build_prefix_value_command("24A", 10),

        # Parameter (ID 0x41, prefix "251", Handler B - direct hex)
        'param_0': build_prefix_value_command("251", 0),
        'param_1': build_prefix_value_command("251", 1),
        'param_2': build_prefix_value_command("251", 2),
        'param_3': build_prefix_value_command("251", 3),
        'param_4': build_prefix_value_command("251", 4),
        'param_5': build_prefix_value_command("251", 5),
        'param_6': build_prefix_value_command("251", 6),
        'param_7': build_prefix_value_command("251", 7),
        'param_8': build_prefix_value_command("251", 8),
        'param_9': build_prefix_value_command("251", 9),
        'param_10': build_prefix_value_command("251", 10),

        # Zone 2 Balance (ID 0x42, prefix "252", Handler B - direct hex)
        'zone2_balance_0': build_prefix_value_command("252", 0),
        'zone2_balance_1': build_prefix_value_command("252", 1),
        'zone2_balance_2': build_prefix_value_command("252", 2),
        'zone2_balance_3': build_prefix_value_command("252", 3),
        'zone2_balance_4': build_prefix_value_command("252", 4),
        'zone2_balance_5': build_prefix_value_command("252", 5),
        'zone2_balance_6': build_prefix_value_command("252", 6),
        'zone2_balance_7': build_prefix_value_command("252", 7),
        'zone2_balance_8': build_prefix_value_command("252", 8),
        'zone2_balance_9': build_prefix_value_command("252", 9),
        'zone2_balance_10': build_prefix_value_command("252", 10),

        # Zone 3 Balance (ID 0x43, prefix "253", Handler B - direct hex)
        'zone3_balance_0': build_prefix_value_command("253", 0),
        'zone3_balance_1': build_prefix_value_command("253", 1),
        'zone3_balance_2': build_prefix_value_command("253", 2),
        'zone3_balance_3': build_prefix_value_command("253", 3),
        'zone3_balance_4': build_prefix_value_command("253", 4),
        'zone3_balance_5': build_prefix_value_command("253", 5),
        'zone3_balance_6': build_prefix_value_command("253", 6),
        'zone3_balance_7': build_prefix_value_command("253", 7),
        'zone3_balance_8': build_prefix_value_command("253", 8),
        'zone3_balance_9': build_prefix_value_command("253", 9),
        'zone3_balance_10': build_prefix_value_command("253", 10),

        # Zone 4 Balance (ID 0x44, prefix "254", Handler B - direct hex)
        'zone4_balance_0': build_prefix_value_command("254", 0),
        'zone4_balance_1': build_prefix_value_command("254", 1),
        'zone4_balance_2': build_prefix_value_command("254", 2),
        'zone4_balance_3': build_prefix_value_command("254", 3),
        'zone4_balance_4': build_prefix_value_command("254", 4),
        'zone4_balance_5': build_prefix_value_command("254", 5),
        'zone4_balance_6': build_prefix_value_command("254", 6),
        'zone4_balance_7': build_prefix_value_command("254", 7),
        'zone4_balance_8': build_prefix_value_command("254", 8),
        'zone4_balance_9': build_prefix_value_command("254", 9),
        'zone4_balance_10': build_prefix_value_command("254", 10),

        # Zone 2 Volume Level (ID 0x48, prefix "261", Handler B - direct hex)
        'zone2_vol_level_0': build_prefix_value_command("261", 0),
        'zone2_vol_level_1': build_prefix_value_command("261", 1),
        'zone2_vol_level_2': build_prefix_value_command("261", 2),
        'zone2_vol_level_3': build_prefix_value_command("261", 3),
        'zone2_vol_level_4': build_prefix_value_command("261", 4),
        'zone2_vol_level_5': build_prefix_value_command("261", 5),
        'zone2_vol_level_6': build_prefix_value_command("261", 6),
        'zone2_vol_level_7': build_prefix_value_command("261", 7),
        'zone2_vol_level_8': build_prefix_value_command("261", 8),
        'zone2_vol_level_9': build_prefix_value_command("261", 9),
        'zone2_vol_level_10': build_prefix_value_command("261", 10),

        # Zone 3 Volume Level (ID 0x49, prefix "262", Handler B - direct hex)
        'zone3_vol_level_0': build_prefix_value_command("262", 0),
        'zone3_vol_level_1': build_prefix_value_command("262", 1),
        'zone3_vol_level_2': build_prefix_value_command("262", 2),
        'zone3_vol_level_3': build_prefix_value_command("262", 3),
        'zone3_vol_level_4': build_prefix_value_command("262", 4),
        'zone3_vol_level_5': build_prefix_value_command("262", 5),
        'zone3_vol_level_6': build_prefix_value_command("262", 6),
        'zone3_vol_level_7': build_prefix_value_command("262", 7),
        'zone3_vol_level_8': build_prefix_value_command("262", 8),
        'zone3_vol_level_9': build_prefix_value_command("262", 9),
        'zone3_vol_level_10': build_prefix_value_command("262", 10),

        # === NEW: Special ID 0xff Command ===
        # Fixed frame: 0x11 '0' '0' '0' 0x03
        'special_0xff': b'\x11000\x03',

        # === Phase 1: Inquiry/Query Commands (recovered from RE) ===
        # ID 0x2e value 1 -> record "00000" -> STX + "00000" + ETX
        'query_init': b'\x0200000\x03',
        # ID 0x2f value N -> record "2010N" -> STX + "2010N" + ETX
        'query_page_0': b'\x02020100\x03',
        'query_page_1': b'\x02020101\x03',
        'query_page_2': b'\x02020102\x03',
        'query_page_3': b'\x02020103\x03',
        'query_page_4': b'\x02020104\x03',
        'query_page_5': b'\x02020105\x03',
        'query_page_6': b'\x02020106\x03',
        'query_page_7': b'\x02020107\x03',
        'query_page_8': b'\x02020108\x03',

        # === NEW: Additional Full-Record Commands from RE ===
        # Input Selection (ID 0x02, all 13 records).  Values are the reported
        # input value from field 0x21; 07ACA/07AC8 are aliases of 07AC0/07A13.
        'input_phono': b'\x0207A14\x03',        # -> 0x00 PHONO
        'input_cd': b'\x0207A15\x03',           # -> 0x01 CD
        'input_tuner': b'\x0207A16\x03',        # -> 0x02 TUNER
        'input_cdr': b'\x0207A19\x03',          # -> 0x03 CD-R
        'input_md_tape': b'\x0207AC9\x03',      # -> 0x04 MD/TAPE
        'input_dvd': b'\x0207AC1\x03',          # -> 0x05 DVD
        'input_dtv': b'\x0207A54\x03',          # -> 0x06 DTV
        'input_cbl_sat': b'\x0207AC0\x03',      # -> 0x07 CBL/SAT
        'input_cbl_sat_alias': b'\x0207ACA\x03',  # -> 0x07 (alias)
        'input_vcr1': b'\x0207A0F\x03',         # -> 0x09 VCR1
        'input_dvr_vcr2': b'\x0207A13\x03',     # -> 0x0A DVR/VCR2
        'input_dvr_vcr2_alias': b'\x0207AC8\x03',  # -> 0x0A (alias)
        'input_vaux': b'\x0207A55\x03',         # -> 0x0C V-AUX

        # Sound Modes - Additional (from ID 0x06)
        'sound_stereo': b'\x0207E80\x03',
        'sound_dolby': b'\x0207E81\x03',
        'sound_dts': b'\x0207E82\x03',
        'sound_pcm': b'\x0207E83\x03',
        'sound_stereo_2': b'\x0207E84\x03',
        'sound_stereo_3': b'\x0207E85\x03',
        'sound_stereo_4': b'\x0207E86\x03',
        'sound_stereo_5': b'\x0207E87\x03',

        # Surround Modes - Additional (from ID 0x07)
        'surround_dolby_digital': b'\x0207E7C\x03',
        'surround_dts': b'\x0207E7D\x03',
        'surround_stereo': b'\x0207EB9\x03',

        # Zone 2 (from ID 0x08)
        'zone2_power_on': b'\x0207A1E\x03',
        'zone2_power_off': b'\x0207A1D\x03',

        # Zone 3 (from ID 0x09)
        'zone3_power_on': b'\x0207E7F\x03',
        'zone3_power_off': b'\x0207E7E\x03',

        # System (from ID 0x0a)
        'system_power_on': b'\x0207EBB\x03',
        'system_power_off': b'\x0207EBA\x03',

        # OSD (from ID 0x0b)
        'osd_on': b'\x0207AEE\x03',
        'osd_off': b'\x0207AED\x03',

        # On Screen Display (from ID 0x0c)
        'on_screen_display': b'\x0207E66\x03',
        'on_screen_display_2': b'\x0207E26\x03',

        # Fl Volume (from ID 0x0d)
        'fl_volume': b'\x0207AFE\x03',
        'fl_volume_2': b'\x0207AFD\x03',

        # Sleep (from ID 0x0e)
        'sleep_on': b'\x0207AF1\x03',
        'sleep_off': b'\x0207AF2\x03',
        'sleep_auto': b'\x0207AF3\x03',
        'sleep_timer': b'\x0207AF5\x03',

        # OSD 2 (from ID 0x0f)
        'osd_2_on': b'\x0207EB2\x03',
        'osd_2_off': b'\x0207EB1\x03',
        'osd_2_auto': b'\x0207EB0\x03',

        # Input Select (from ID 0x10)
        'input_select_1': b'\x0207EB4\x03',
        'input_select_2': b'\x0207EB5\x03',
        'input_select_3': b'\x0207EB6\x03',
        'input_select_4': b'\x0207EB7\x03',

        # Input Select 2 (from ID 0x11)
        'input_select_2_1': b'\x0207EB9\x03',
        'input_select_2_2': b'\x0207EB8\x03',
        'input_select_2_3': b'\x0207E7D\x03',
        'input_select_2_4': b'\x0207E7C\x03',

        # Night Mode (from ID 0x12)
        'night_mode_on': b'\x0207E9C\x03',
        'night_mode_off': b'\x0207E9B\x03',

        # Straight (from ID 0x13)
        'straight_on': b'\x0207EE0\x03',
        'straight_off': b'\x0207E27\x03',

        # Sound Mode (from ID 0x14)
        'sound_mode_1': b'\x0207EE1\x03',
        'sound_mode_2': b'\x0207EE2\x03',
        'sound_mode_3': b'\x0207EE3\x03',
        'sound_mode_4': b'\x0207EE4\x03',
        'sound_mode_5': b'\x0207EE5\x03',
        'sound_mode_6': b'\x0207EE6\x03',
        'sound_mode_7': b'\x0207EE7\x03',
        'sound_mode_8': b'\x0207EE8\x03',
        'sound_mode_9': b'\x0207EE9\x03',
        'sound_mode_10': b'\x0207EEA\x03',
        'sound_mode_11': b'\x0207EEB\x03',
        'sound_mode_12': b'\x0207EEC\x03',
        'sound_mode_13': b'\x0207EED\x03',
        'sound_mode_14': b'\x0207EEE\x03',
        'sound_mode_15': b'\x0207EEF\x03',
        'sound_mode_16': b'\x0207EF0\x03',
        'sound_mode_17': b'\x0207EF1\x03',
        'sound_mode_18': b'\x0207EF2\x03',
        'sound_mode_19': b'\x0207EFF\x03',
        'sound_mode_20': b'\x0207EF3\x03',
        'sound_mode_21': b'\x0207EF4\x03',
        'sound_mode_22': b'\x0207EF5\x03',
        'sound_mode_23': b'\x0207EF6\x03',
        'sound_mode_24': b'\x0207EF7\x03',
        'sound_mode_25': b'\x0207EF8\x03',
        'sound_mode_26': b'\x0207EF9\x03',
        'sound_mode_27': b'\x0207EFA\x03',
        'sound_mode_28': b'\x0207EFB\x03',
        'sound_mode_29': b'\x0207EFC\x03',
        'sound_mode_30': b'\x0207EFD\x03',
        'sound_mode_31': b'\x0207EFE\x03',
        'sound_mode_32': b'\x0207E67\x03',
        'sound_mode_33': b'\x0207E68\x03',
        'sound_mode_34': b'\x0207E69\x03',
        'sound_mode_35': b'\x0207E6A\x03',
        'sound_mode_36': b'\x0207EC1\x03',
        'sound_mode_37': b'\x0207EC0\x03',
        'sound_mode_38': b'\x0207EC2\x03',
        'sound_mode_39': b'\x0207EC3\x03',

        # Volume Memory (from ID 0x15)
        'vol_memory_1': b'\x0207E70\x03',
        'vol_memory_2': b'\x0207E71\x03',
        'vol_memory_3': b'\x0207E72\x03',
        'vol_memory_4': b'\x0207E73\x03',
        'vol_memory_5': b'\x0207E74\x03',

        # Volume Memory 2 (from ID 0x16)
        'vol_memory_2_1': b'\x0207E75\x03',
        'vol_memory_2_2': b'\x0207E76\x03',
        'vol_memory_2_3': b'\x0207E77\x03',
        'vol_memory_2_4': b'\x0207E78\x03',
        'vol_memory_2_5': b'\x0207E79\x03',
        'vol_memory_2_6': b'\x0207E7A\x03',

        # Volume Memory 3 (from ID 0x17)
        'vol_memory_3_1': b'\x0207E87\x03',
        'vol_memory_3_2': b'\x0207E88\x03',
        'vol_memory_3_3': b'\x0207E89\x03',
        'vol_memory_3_4': b'\x0207E8A\x03',
        'vol_memory_3_5': b'\x0207E8B\x03',
        'vol_memory_3_6': b'\x0207E8C\x03',

        # Volume Memory 4 (from ID 0x18)
        'vol_memory_4_1': b'\x0207E8D\x03',
        'vol_memory_4_2': b'\x0207E8E\x03',
        'vol_memory_4_3': b'\x0207E8F\x03',
        'vol_memory_4_4': b'\x0207E90\x03',
        'vol_memory_4_5': b'\x0207E91\x03',
        'vol_memory_4_6': b'\x0207E92\x03',

        # Volume Memory 5 (from ID 0x19)
        'vol_memory_5_1': b'\x0207E20\x03',
        'vol_memory_5_2': b'\x0207E21\x03',
        'vol_memory_5_3': b'\x0207E22\x03',
        'vol_memory_5_4': b'\x0207E23\x03',
        'vol_memory_5_5': b'\x0207E24\x03',
        'vol_memory_5_6': b'\x0207E25\x03',

        # Volume Memory 6 (from ID 0x1a)
        'vol_memory_6_1': b'\x0207E60\x03',
        'vol_memory_6_2': b'\x0207E61\x03',
        'vol_memory_6_3': b'\x0207E62\x03',
        'vol_memory_6_4': b'\x0207E63\x03',
        'vol_memory_6_5': b'\x0207E64\x03',
        'vol_memory_6_6': b'\x0207E65\x03',

        # Volume Memory 7 (from ID 0x1b)
        'vol_memory_7_1': b'\x0207E34\x03',
        'vol_memory_7_2': b'\x0207E32\x03',
        'vol_memory_7_3': b'\x0207E33\x03',
        'vol_memory_7_4': b'\x0207E31\x03',

        # Volume Memory 8 (from ID 0x1c)
        'vol_memory_8_1': b'\x0207E72\x03',
        'vol_memory_8_2': b'\x0207E71\x03',

        # Volume Memory 9 (from ID 0x1d)
        'vol_memory_9_1': b'\x0207E74\x03',
        'vol_memory_9_2': b'\x0207E73\x03',

        # Volume Memory 10 (from ID 0x1e)
        'vol_memory_10_1': b'\x0207E84\x03',
        'vol_memory_10_2': b'\x0207E83\x03',

        # Volume Memory 11 (from ID 0x1f)
        'vol_memory_11_1': b'\x0207E93\x03',
        'vol_memory_11_2': b'\x0207E94\x03',
        'vol_memory_11_3': b'\x0207E95\x03',

        # Volume Memory 12 (from ID 0x20)
        'vol_memory_12_1': b'\x0207E98\x03',
        'vol_memory_12_2': b'\x0207E96\x03',
        'vol_memory_12_3': b'\x0207E97\x03',
        'vol_memory_12_4': b'\x0207E9F\x03',

        # Volume Memory 13 (from ID 0x21)
        'vol_memory_13_1': b'\x0207E3D\x03',
        'vol_memory_13_2': b'\x0207E3C\x03',

        # Volume Memory 14 (from ID 0x22)
        'vol_memory_14_1': b'\x0207E3F\x03',
        'vol_memory_14_2': b'\x0207E3E\x03',

        # Volume Memory 15 (from ID 0x23)
        'vol_memory_15_1': b'\x0207E86\x03',
        'vol_memory_15_2': b'\x0207E85\x03',

        # Volume Memory 16 (from ID 0x24)
        'vol_memory_16_1': b'\x0207E28\x03',
        'vol_memory_16_2': b'\x0207E29\x03',

        # Volume Memory 17 (from ID 0x25)
        'vol_memory_17_1': b'\x0207E9A\x03',
        'vol_memory_17_2': b'\x0207E99\x03',

        # Volume Memory 18 (from ID 0x26)
        'vol_memory_18_1': b'\x0207EBC\x03',
        'vol_memory_18_2': b'\x0207EBD\x03',

        # Volume Memory 19 (from ID 0x27)
        'vol_memory_19_1': b'\x0207EBE\x03',
        'vol_memory_19_2': b'\x0207EBF\x03',

        # Volume Memory 20 (from ID 0x28)
        'vol_memory_20_1': b'\x0207EAC\x03',
        'vol_memory_20_2': b'\x0207EAB\x03',

        # Volume Memory 21 (from ID 0x29)
        'vol_memory_21_1': b'\x0207EAE\x03',
        'vol_memory_21_2': b'\x0207EAD\x03',

        # Volume Memory 22 (from ID 0x2a)
        'vol_memory_22_1': b'\x0207E2B\x03',
        'vol_memory_22_2': b'\x0207E2C\x03',
        'vol_memory_22_3': b'\x0207E2D\x03',
        'vol_memory_22_4': b'\x0207E2E\x03',
        'vol_memory_22_5': b'\x0207E2F\x03',
        'vol_memory_22_6': b'\x0207E30\x03',

        # Volume Memory 23 (from ID 0x2b)
        'vol_memory_23_1': b'\x0207E35\x03',
        'vol_memory_23_2': b'\x0207E36\x03',
        'vol_memory_23_3': b'\x0207E37\x03',
        'vol_memory_23_4': b'\x0207E38\x03',
        'vol_memory_23_5': b'\x0207E39\x03',
        'vol_memory_23_6': b'\x0207E3A\x03',

        # Volume Memory 24 (from ID 0x2c)
        'vol_memory_24_1': b'\x0207E6B\x03',
        'vol_memory_24_2': b'\x0207E6C\x03',
        'vol_memory_24_3': b'\x0207E6D\x03',
        'vol_memory_24_4': b'\x0207E6E\x03',
        'vol_memory_24_5': b'\x0207E6F\x03',
        'vol_memory_24_6': b'\x0207E70\x03',

        # Volume Memory 25 (from ID 0x2d)
        'vol_memory_25_1': b'\x0207E75\x03',
        'vol_memory_25_2': b'\x0207E76\x03',
        'vol_memory_25_3': b'\x0207E77\x03',
        'vol_memory_25_4': b'\x0207E78\x03',
        'vol_memory_25_5': b'\x0207E79\x03',
        'vol_memory_25_6': b'\x0207E7A\x03',

        # Volume Memory 26 (from ID 0x2e)
        'vol_memory_26_1': b'\x0207E87\x03',
        'vol_memory_26_2': b'\x0207E88\x03',
        'vol_memory_26_3': b'\x0207E89\x03',
        'vol_memory_26_4': b'\x0207E8A\x03',
        'vol_memory_26_5': b'\x0207E8B\x03',
        'vol_memory_26_6': b'\x0207E8C\x03',

        # Volume Memory 27 (from ID 0x2f)
        'vol_memory_27_1': b'\x0207E8D\x03',
        'vol_memory_27_2': b'\x0207E8E\x03',
        'vol_memory_27_3': b'\x0207E8F\x03',
        'vol_memory_27_4': b'\x0207E90\x03',
        'vol_memory_27_5': b'\x0207E91\x03',
        'vol_memory_27_6': b'\x0207E92\x03',

        # Volume Memory 28 (from ID 0x33)
        'vol_memory_28_1': b'\x0207E20\x03',
        'vol_memory_28_2': b'\x0207E21\x03',
        'vol_memory_28_3': b'\x0207E22\x03',
        'vol_memory_28_4': b'\x0207E23\x03',
        'vol_memory_28_5': b'\x0207E24\x03',
        'vol_memory_28_6': b'\x0207E25\x03',

        # Volume Memory 29 (from ID 0x35)
        'vol_memory_29_1': b'\x0207E60\x03',
        'vol_memory_29_2': b'\x0207E61\x03',
        'vol_memory_29_3': b'\x0207E62\x03',
        'vol_memory_29_4': b'\x0207E63\x03',
        'vol_memory_29_5': b'\x0207E64\x03',
        'vol_memory_29_6': b'\x0207E65\x03',

        # Volume Memory 30 (from ID 0x46)
        'vol_memory_30_1': b'\x0207E72\x03',
        'vol_memory_30_2': b'\x0207E71\x03',

        # Volume Memory 31 (from ID 0x47)
        'vol_memory_31_1': b'\x0207E74\x03',
        'vol_memory_31_2': b'\x0207E73\x03',

        # Volume Memory 32 (from ID 0x4a)
        'vol_memory_32_1': b'\x0207E84\x03',
        'vol_memory_32_2': b'\x0207E83\x03',

        # Volume Memory 33 (from ID 0x4b)
        'vol_memory_33_1': b'\x0207E93\x03',
        'vol_memory_33_2': b'\x0207E94\x03',
        'vol_memory_33_3': b'\x0207E95\x03',

        # Volume Memory 34 (from ID 0x4c)
        'vol_memory_34_1': b'\x0207E98\x03',
        'vol_memory_34_2': b'\x0207E96\x03',
        'vol_memory_34_3': b'\x0207E97\x03',
        'vol_memory_34_4': b'\x0207E9F\x03',

        # Volume Memory 35 (from ID 0x4d)
        'vol_memory_35_1': b'\x0207E3D\x03',
        'vol_memory_35_2': b'\x0207E3C\x03',

        # Volume Memory 36 (from ID 0x4e)
        'vol_memory_36_1': b'\x0207E3F\x03',
        'vol_memory_36_2': b'\x0207E3E\x03',

        # Volume Memory 37 (from ID 0x4f)
        'vol_memory_37_1': b'\x0207E86\x03',
        'vol_memory_37_2': b'\x0207E85\x03',

        # Volume Memory 38 (from ID 0x50)
        'vol_memory_38_1': b'\x0207E28\x03',
        'vol_memory_38_2': b'\x0207E29\x03',

        # Volume Memory 39 (from ID 0x51)
        'vol_memory_39_1': b'\x0207E9A\x03',
        'vol_memory_39_2': b'\x0207E99\x03',

        # Volume Memory 40 (from ID 0x52)
        'vol_memory_40_1': b'\x0207EBC\x03',
        'vol_memory_40_2': b'\x0207EBD\x03',

        # Volume Memory 41 (from ID 0x53)
        'vol_memory_41_1': b'\x0207EBE\x03',
        'vol_memory_41_2': b'\x0207EBF\x03',

        # Volume Memory 42 (from ID 0x54)
        'vol_memory_42_1': b'\x0207EAC\x03',
        'vol_memory_42_2': b'\x0207EAB\x03',

        # Volume Memory 43 (from ID 0x55)
        'vol_memory_43_1': b'\x0207EAE\x03',
        'vol_memory_43_2': b'\x0207EAD\x03',

        # Volume Memory 44 (from ID 0x56)
        'vol_memory_44_1': b'\x0207E2B\x03',
        'vol_memory_44_2': b'\x0207E2C\x03',
        'vol_memory_44_3': b'\x0207E2D\x03',
        'vol_memory_44_4': b'\x0207E2E\x03',
        'vol_memory_44_5': b'\x0207E2F\x03',
        'vol_memory_44_6': b'\x0207E30\x03',

        # Volume Memory 45 (from ID 0x57)
        'vol_memory_45_1': b'\x0207E35\x03',
        'vol_memory_45_2': b'\x0207E36\x03',
        'vol_memory_45_3': b'\x0207E37\x03',
        'vol_memory_45_4': b'\x0207E38\x03',
        'vol_memory_45_5': b'\x0207E39\x03',
        'vol_memory_45_6': b'\x0207E3A\x03',

        # Volume Memory 46 (from ID 0x58)
        'vol_memory_46_1': b'\x0207E6B\x03',
        'vol_memory_46_2': b'\x0207E6C\x03',
        'vol_memory_46_3': b'\x0207E6D\x03',
        'vol_memory_46_4': b'\x0207E6E\x03',
        'vol_memory_46_5': b'\x0207E6F\x03',
        'vol_memory_46_6': b'\x0207E70\x03',

        # Volume Memory 47 (from ID 0x59)
        'vol_memory_47_1': b'\x0207E75\x03',
        'vol_memory_47_2': b'\x0207E76\x03',
        'vol_memory_47_3': b'\x0207E77\x03',
        'vol_memory_47_4': b'\x0207E78\x03',
        'vol_memory_47_5': b'\x0207E79\x03',
        'vol_memory_47_6': b'\x0207E7A\x03',

        # Volume Memory 48 (from ID 0x5a)
        'vol_memory_48_1': b'\x0207E87\x03',
        'vol_memory_48_2': b'\x0207E88\x03',
        'vol_memory_48_3': b'\x0207E89\x03',
        'vol_memory_48_4': b'\x0207E8A\x03',
        'vol_memory_48_5': b'\x0207E8B\x03',
        'vol_memory_48_6': b'\x0207E8C\x03',

        # Volume Memory 49 (from ID 0x5b)
        'vol_memory_49_1': b'\x0207E8D\x03',
        'vol_memory_49_2': b'\x0207E8E\x03',
        'vol_memory_49_3': b'\x0207E8F\x03',
        'vol_memory_49_4': b'\x0207E90\x03',
        'vol_memory_49_5': b'\x0207E91\x03',
        'vol_memory_49_6': b'\x0207E92\x03',

        # Volume Memory 50 (from ID 0x5c)
        'vol_memory_50_1': b'\x0207E20\x03',
        'vol_memory_50_2': b'\x0207E21\x03',
        'vol_memory_50_3': b'\x0207E22\x03',
        'vol_memory_50_4': b'\x0207E23\x03',
        'vol_memory_50_5': b'\x0207E24\x03',
        'vol_memory_50_6': b'\x0207E25\x03',

        # Volume Memory 51 (from ID 0x5d)
        'vol_memory_51_1': b'\x0207E60\x03',
        'vol_memory_51_2': b'\x0207E61\x03',
        'vol_memory_51_3': b'\x0207E62\x03',
        'vol_memory_51_4': b'\x0207E63\x03',
        'vol_memory_51_5': b'\x0207E64\x03',
        'vol_memory_51_6': b'\x0207E65\x03',

        # Volume Memory 52 (from ID 0x5e)
        'vol_memory_52_1': b'\x0207E72\x03',
        'vol_memory_52_2': b'\x0207E71\x03',

        # Volume Memory 53 (from ID 0x5f)
        'vol_memory_53_1': b'\x0207E74\x03',
        'vol_memory_53_2': b'\x0207E73\x03',

        # Volume Memory 54 (from ID 0x60)
        'vol_memory_54_1': b'\x0207E84\x03',
        'vol_memory_54_2': b'\x0207E83\x03',

        # Volume Memory 55 (from ID 0x61)
        'vol_memory_55_1': b'\x0207E93\x03',
        'vol_memory_55_2': b'\x0207E94\x03',
        'vol_memory_55_3': b'\x0207E95\x03',

        # Volume Memory 56 (from ID 0x62)
        'vol_memory_56_1': b'\x0207E98\x03',
        'vol_memory_56_2': b'\x0207E96\x03',
        'vol_memory_56_3': b'\x0207E97\x03',
        'vol_memory_56_4': b'\x0207E9F\x03',

        # Volume Memory 57 (from ID 0x63)
        'vol_memory_57_1': b'\x0207E3D\x03',
        'vol_memory_57_2': b'\x0207E3C\x03',

        # Volume Memory 58 (from ID 0x64)
        'vol_memory_58_1': b'\x0207E3F\x03',
        'vol_memory_58_2': b'\x0207E3E\x03',

        # Volume Memory 59 (from ID 0x65)
        'vol_memory_59_1': b'\x0207E86\x03',
        'vol_memory_59_2': b'\x0207E85\x03',

        # Volume Memory 60 (from ID 0x66)
        'vol_memory_60_1': b'\x0207E28\x03',
        'vol_memory_60_2': b'\x0207E29\x03',

        # Volume Memory 61 (from ID 0x67)
        'vol_memory_61_1': b'\x0207E9A\x03',
        'vol_memory_61_2': b'\x0207E99\x03',

        # Volume Memory 62 (from ID 0x68)
        'vol_memory_62_1': b'\x0207EBC\x03',
        'vol_memory_62_2': b'\x0207EBD\x03',

        # Volume Memory 63 (from ID 0x69)
        'vol_memory_63_1': b'\x0207EBE\x03',
        'vol_memory_63_2': b'\x0207EBF\x03',

        # Volume Memory 64 (from ID 0x6a)
        'vol_memory_64_1': b'\x0207EAC\x03',
        'vol_memory_64_2': b'\x0207EAB\x03',

        # Volume Memory 65 (from ID 0x6b)
        'vol_memory_65_1': b'\x0207EAE\x03',
        'vol_memory_65_2': b'\x0207EAD\x03',

        # Volume Memory 66 (from ID 0x6c)
        'vol_memory_66_1': b'\x0207E2B\x03',
        'vol_memory_66_2': b'\x0207E2C\x03',
        'vol_memory_66_3': b'\x0207E2D\x03',
        'vol_memory_66_4': b'\x0207E2E\x03',
        'vol_memory_66_5': b'\x0207E2F\x03',
        'vol_memory_66_6': b'\x0207E30\x03',
    }

    # DIP Protocol commands (for direct TCP on port 2500)
    # Based on Untitled.md - System ID 0230, commands use 2109 (Write)
    COMMANDS_DIP = {
        # Power - Address 0004, Data: 01=ON, 00=OFF
        'power_on': b'\x14210902300004010220\x03',
        'power_off': b'\x14210902300004000230\x03',

        # Volume - Address 0000, Data: 4-byte hex (0C80 = -30dB as example)
        # Note: Volume commands need to be constructed with actual values
        # These are placeholders - may need adjustment
        'vol_up': None,  # Requires reading current volume first
        'vol_down': None,  # Requires reading current volume first
        'mute_on': None,  # Address TBD
        'mute_off': None,  # Address TBD

        # Input Selection - Addresses TBD from your testing
        'input_phono': None,
        'input_cd': None,
        'input_tuner': None,
        'input_cdr': None,
        'input_md_tape': None,
        'input_dvd': None,
        'input_dtv_ld': None,
        'input_cbl_sat': None,
        'input_vcr1': None,
        'input_dvr_vcr2': None,
        'input_vaux': None,
        'input_multi': None,

        # Sound Mode - Addresses TBD
        'straight_on': None,
        'straight_off': None,
        'night_on': None,
        'night_off': None,

        # OSD - Addresses TBD
        'osd_on': None,
        'osd_off': None,
    }

    def __init__(self, host: str, port: int = 2500, timeout: float = 2.0, protocol: str = None):
        """
        Initialize the controller.

        Args:
            host: IP address of receiver
            port: TCP port (default: 2500 for direct network, 3333 for ser2net)
            timeout: Socket timeout in seconds
            protocol: 'rs232' or 'dip' (uses 'rs232' by default - works on both ports)
        """
        self.host = host
        self.port = port
        self.timeout = timeout

        # Use RS-232 protocol by default (works on both port 2500 and 3333)
        self.protocol = protocol if protocol else self.PROTOCOL_RS232

        # Persistent connection state (Phase 1: read-back support)
        self._sock: Optional[socket.socket] = None

        # Report parser for decoding status reports
        self.parser = ReportParser()

    # Phase 1: Inquiry frames recovered from RE analysis
    # ID 0x2e value 1 -> record "00000" -> STX + "00000" + ETX
    QUERY_INIT = b'\x0200000\x03'

    @staticmethod
    def set_volume_frame(raw: int) -> bytes:
        """Build an absolute main-volume frame for raw value 0..188.

        Encoding (handler 0x42a4fd; offset corrected 2026-10-12 by panel
        calibration — the RE'd 0x26 was off by one): wire = raw +
        VOLUME_WIRE_OFFSET for raw != 0, wire = 0x00 for raw == 0.
        Frame = STX + "230" + hex(wire) + ETX.  The receiver echoes
        "30 26 <wire>" (type 0x30) and applies the change SILENTLY —
        no state report ever follows a "230" set.
        """
        if not 0 <= raw <= 188:
            raise ValueError(f"raw volume must be 0..188, got {raw}")
        wire = raw + VOLUME_WIRE_OFFSET if raw != 0 else 0
        return f"\x02230{wire:02X}\x03".encode('ascii')
    # ID 0x2f value N -> record "2010N" -> STX + "2010N" + ETX
    @staticmethod
    def query_page_frame(page: int) -> bytes:
        """Build a data-page inquiry frame: STX + '2010N' + ETX."""
        if not 0 <= page <= 8:
            raise ValueError(f"Page must be 0-8, got {page}")
        record = f"2010{page}"
        return f"\x02{record}\x03".encode('ascii')

    def connect(self):
        """Open a persistent TCP connection to the receiver."""
        if self._sock is not None:
            return
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect((self.host, self.port))

    def disconnect(self):
        """Close the persistent connection."""
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def _send_dip_handshake(self, sock: socket.socket) -> bool:
        """
        Send DIP protocol handshake sequence.

        Args:
            sock: Connected socket

        Returns:
            True if handshake appears successful (or attempted)
        """
        try:
            # Step 1: INIT
            sock.sendall(self.HANDSHAKE_INIT)
            time.sleep(0.5)

            # Step 2: System Query
            sock.sendall(self.HANDSHAKE_SYSTEM_QUERY)
            time.sleep(0.5)

            # Try to read response (may get NACK if receiver config is locked)
            try:
                response = sock.recv(512)
                if b'2103FFFF' in response or b'Port already' in response:
                    return False  # Known error responses
            except socket.timeout:
                pass  # No response is okay for handshake

            return True

        except Exception:
            return False

    def send_command(self, command: bytes, expect_response: bool = False,
                     persistent: bool = False) -> Optional[bytes]:
        """
        Send a command to the receiver.

        Args:
            command: Raw command bytes to send
            expect_response: Whether to wait for a response
            persistent: If True, reuse the persistent connection (call connect() first)

        Returns:
            Response bytes if expect_response=True, otherwise None

        Raises:
            ConnectionError: If unable to connect
            TimeoutError: If no response received when expected
        """
        if persistent and self._sock is not None:
            try:
                self._sock.sendall(command)
                if expect_response:
                    time.sleep(0.1)
                    try:
                        return self._sock.recv(512)
                    except socket.timeout:
                        return None
                return None
            except socket.error as e:
                self.disconnect()
                raise ConnectionError(f"Persistent connection failed: {e}")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((self.host, self.port))

                # Send command (RS-232 protocol works directly on port 2500)
                sock.sendall(command)

                if expect_response:
                    time.sleep(0.1)  # Brief delay for receiver to respond
                    try:
                        response = sock.recv(512)
                        return response
                    except socket.timeout:
                        return None

                return None

        except socket.error as e:
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}: {e}")

    def listen(self, duration: float = 5.0):
        """
        Connect and dump all bytes received from the receiver for a duration.

        Args:
            duration: How long to listen in seconds
        """
        self.connect()
        self._sock.settimeout(0.5)
        print(f"Listening on {self.host}:{self.port} for {duration}s (Ctrl-C to stop)...")
        start = time.time()
        buffer = b''
        try:
            while time.time() - start < duration:
                try:
                    data = self._sock.recv(4096)
                    if data:
                        ts = time.time() - start
                        hex_str = data.hex(' ')
                        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
                        print(f"[{ts:6.2f}s] HEX: {hex_str}")
                        print(f"           ASCII: {ascii_str}")
                        buffer += data
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self._sock.settimeout(self.timeout)

        print(f"\nTotal bytes received: {len(buffer)}")
        if buffer:
            print(f"Raw hex: {buffer.hex(' ')}")
        return buffer

    def query(self, pages: list = None, delay: float = 0.15):
        """
        Send inquiry frames and collect responses.

        Args:
            pages: List of page numbers to query (default: all 0-8)
            delay: Delay between frames in seconds

        Returns:
            dict mapping page number to response bytes (or None)
        """
        if pages is None:
            pages = list(range(9))

        self.connect()
        results = {}

        # Send init frame
        print(f"Sending QUERY_INIT: {self.QUERY_INIT.hex(' ')}")
        self._sock.sendall(self.QUERY_INIT)
        time.sleep(delay)

        for page in pages:
            frame = self.query_page_frame(page)
            print(f"Sending page {page}: {frame.hex(' ')}")
            self._sock.sendall(frame)
            time.sleep(delay)

            # Try to read response
            self._sock.settimeout(0.5)
            try:
                response = self._sock.recv(4096)
                if response:
                    results[page] = response
                    hex_str = response.hex(' ')
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in response)
                    print(f"  -> Response ({len(response)} bytes): {hex_str}")
                    print(f"     ASCII: {ascii_str}")
                else:
                    results[page] = None
                    print(f"  -> No response")
            except socket.timeout:
                results[page] = None
                print(f"  -> Timeout (no response)")

        self._sock.settimeout(self.timeout)
        return results

    def monitor(self, duration: float = 30.0, state_file: str = None):
        """
        Listen for reports, decode them, and maintain state.

        Args:
            duration: How long to listen in seconds
            state_file: If provided, write state JSON to this file
        """
        self.connect()
        self._sock.settimeout(0.5)
        start = time.time()
        buf = b''

        print(f"Monitoring for {duration}s (Ctrl-C to stop)...")

        try:
            while time.time() - start < duration:
                try:
                    data = self._sock.recv(4096)
                    if data:
                        buf += data
                        while True:
                            stx = buf.find(b'\x02')
                            if stx == -1:
                                buf = b''
                                break
                            etx = buf.find(b'\x03', stx + 1)
                            if etx == -1:
                                buf = buf[stx:]
                                break
                            frame = buf[stx:etx + 1]
                            buf = buf[etx + 1:]

                            report = self.parser.parse_frame(frame)
                            if report:
                                ts = time.time() - start
                                decoded = report.get('decoded', '?')
                                print(f"[{ts:6.2f}s] {decoded}")

                                if state_file:
                                    self._write_state(state_file)
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            pass
        finally:
            self._sock.settimeout(self.timeout)

        print(f"\nFinal state:")
        print(self.parser.get_status_json())

    def status(self, state_file: str = None) -> Dict[str, Any]:
        """
        Print current receiver state.

        Args:
            state_file: Read state from this file (written by monitor)

        Returns:
            Current state dict
        """
        if state_file and os.path.exists(state_file):
            with open(state_file) as f:
                state = json.load(f)
        else:
            state = self.parser.get_status()

        print(json.dumps(state, indent=2))
        return state

    def _write_state(self, state_file: str):
        """Write current state to a JSON file."""
        try:
            with open(state_file, 'w') as f:
                json.dump(self.parser.get_status(), f, indent=2)
        except Exception:
            pass  # Don't let state file errors break monitoring

    def execute(self, command_name: str, repeat: bool = None) -> bool:
        """
        Execute a named command.

        Args:
            command_name: Name of command (e.g., 'power_on', 'vol_up')
            repeat: Send command twice (auto-enabled for volume commands)

        Returns:
            True if command sent successfully

        Raises:
            ValueError: If command name not recognized or not available for protocol
        """
        # Select appropriate command set based on protocol
        commands = self.COMMANDS_DIP if self.protocol == self.PROTOCOL_DIP else self.COMMANDS_RS232

        if command_name not in commands:
            raise ValueError(f"Unknown command: {command_name}")

        command = commands[command_name]

        if command is None:
            raise ValueError(f"Command '{command_name}' not yet implemented for {self.protocol} protocol")

        # Auto-enable repeat for volume/mute commands ONLY when called from command-line
        # (UI handles timing itself to avoid double-increment)
        if repeat is None:
            # Default to True for command-line usage (one-off commands need wake-up)
            repeat = command_name in ['vol_up', 'vol_down', 'mute_on', 'mute_off']

        # Send command
        self.send_command(command)

        # Send again if repeat enabled (for volume wake-up behavior)
        if repeat:
            time.sleep(0.3)  # Short delay between commands
            self.send_command(command)

        return True

    @classmethod
    def list_commands(cls, protocol: str = PROTOCOL_RS232) -> list:
        """Return list of all available command names for given protocol"""
        commands = cls.COMMANDS_DIP if protocol == cls.PROTOCOL_DIP else cls.COMMANDS_RS232
        return sorted([k for k, v in commands.items() if v is not None])

    @classmethod
    def get_command_categories(cls) -> dict:
        """Return commands organized by category"""
        categories = {
            'Power': [],
            'Volume': [],
            'Volume Level (Prefix+Value)': [],
            'Zone 2': [],
            'Zone 3': [],
            'Zone 4': [],
            'Tone Control': [],
            'Balance': [],
            'Loudness': [],
            'Effect': [],
            'Dialog': [],
            'Subwoofer': [],
            'Presence': [],
            'Sleeper': [],
            'Program': [],
            'Parameter': [],
            'Input': [],
            'Speakers': [],
            'Sleep': [],
            'Night Mode': [],
            'Sound Mode - Basic': [],
            'Sound Mode - Stereo': [],
            'Sound Mode - THX': [],
            'Sound Mode - Music Hall': [],
            'Sound Mode - Entertainment': [],
            'Sound Mode - Music': [],
            'Sound Mode - Movie': [],
            'Surround - Standard': [],
            'Surround - Extended': [],
            'DC Trigger': [],
            'OSD': [],
            'System': [],
            'Zone 2 (Full Record)': [],
            'Zone 3 (Full Record)': [],
            'Volume Memory': [],
            'Special': [],
        }

        for cmd in cls.list_commands():
            if cmd.startswith('power_'):
                categories['Power'].append(cmd)
            elif cmd.startswith('vol_up') or cmd.startswith('vol_down') or cmd.startswith('mute_'):
                categories['Volume'].append(cmd)
            elif cmd.startswith('vol_level_'):
                categories['Volume Level (Prefix+Value)'].append(cmd)
            elif cmd.startswith('zone2_'):
                categories['Zone 2'].append(cmd)
            elif cmd.startswith('zone3_'):
                categories['Zone 3'].append(cmd)
            elif cmd.startswith('zone4_'):
                categories['Zone 4'].append(cmd)
            elif cmd.startswith('bass_'):
                categories['Tone Control'].append(cmd)
            elif cmd.startswith('treble_'):
                categories['Tone Control'].append(cmd)
            elif cmd.startswith('balance_'):
                categories['Balance'].append(cmd)
            elif cmd.startswith('loudness_'):
                categories['Loudness'].append(cmd)
            elif cmd.startswith('effect_'):
                categories['Effect'].append(cmd)
            elif cmd.startswith('dialog_'):
                categories['Dialog'].append(cmd)
            elif cmd.startswith('subwoofer_'):
                categories['Subwoofer'].append(cmd)
            elif cmd.startswith('presence_'):
                categories['Presence'].append(cmd)
            elif cmd.startswith('sleeper_'):
                categories['Sleeper'].append(cmd)
            elif cmd.startswith('program_'):
                categories['Program'].append(cmd)
            elif cmd.startswith('param_'):
                categories['Parameter'].append(cmd)
            elif cmd.startswith('input_'):
                categories['Input'].append(cmd)
            elif cmd.startswith('speaker_'):
                categories['Speakers'].append(cmd)
            elif cmd.startswith('sleep_'):
                categories['Sleep'].append(cmd)
            elif cmd.startswith('night_'):
                categories['Night Mode'].append(cmd)
            elif cmd.startswith('pure_') or cmd == 'straight':
                categories['Sound Mode - Basic'].append(cmd)
            elif cmd.startswith('stereo_'):
                categories['Sound Mode - Stereo'].append(cmd)
            elif cmd.startswith('thx_'):
                categories['Sound Mode - THX'].append(cmd)
            elif cmd.startswith('music_hall_'):
                categories['Sound Mode - Music Hall'].append(cmd)
            elif cmd.startswith('entertainment_'):
                categories['Sound Mode - Entertainment'].append(cmd)
            elif cmd.startswith('music_') and not cmd.startswith('music_hall_'):
                categories['Sound Mode - Music'].append(cmd)
            elif cmd.startswith('movie_'):
                categories['Sound Mode - Movie'].append(cmd)
            elif cmd.startswith('surround_'):
                categories['Surround - Standard'].append(cmd)
            elif cmd.startswith('ext_surround_'):
                categories['Surround - Extended'].append(cmd)
            elif cmd.startswith('dc_trigger_'):
                categories['DC Trigger'].append(cmd)
            elif cmd.startswith('osd_'):
                categories['OSD'].append(cmd)
            elif cmd.startswith('system_'):
                categories['System'].append(cmd)
            elif cmd.startswith('on_screen_'):
                categories['OSD'].append(cmd)
            elif cmd.startswith('fl_volume'):
                categories['Volume'].append(cmd)
            elif cmd.startswith('vol_memory_'):
                categories['Volume Memory'].append(cmd)
            elif cmd == 'special_0xff':
                categories['Special'].append(cmd)
            elif cmd.startswith('zone2_power') or cmd.startswith('zone2_vol'):
                categories['Zone 2 (Full Record)'].append(cmd)
            elif cmd.startswith('zone3_power'):
                categories['Zone 3 (Full Record)'].append(cmd)

        return categories


def main():
    """Command-line interface"""
    args = sys.argv[1:]

    # Phase 1: New modes
    if len(args) >= 2 and args[0] == '--listen':
        host = args[1]
        duration = float(args[2]) if len(args) > 2 else 5.0
        controller = YamahaController(host)
        try:
            controller.listen(duration)
        except ConnectionError as e:
            print(f"Connection error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            controller.disconnect()
        return

    if len(args) >= 2 and args[0] == '--query':
        host = args[1]
        controller = YamahaController(host)
        try:
            results = controller.query()
            print(f"\nSummary: {sum(1 for v in results.values() if v)} responses received")
        except ConnectionError as e:
            print(f"Connection error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            controller.disconnect()
        return

    if len(args) >= 2 and args[0] == '--monitor':
        host = args[1]
        duration = float(args[2]) if len(args) > 2 else 30.0
        state_file = args[3] if len(args) > 3 else None
        controller = YamahaController(host)
        try:
            controller.monitor(duration, state_file)
        except ConnectionError as e:
            print(f"Connection error: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            controller.disconnect()
        return

    if len(args) >= 1 and args[0] == '--status':
        state_file = args[1] if len(args) > 1 else None
        controller = YamahaController('localhost')
        controller.status(state_file)
        return

    if len(args) < 2:
        print("Usage: python yamaha_rs232_controller.py <host> <command>")
        print("       python yamaha_rs232_controller.py --listen <host> [seconds]")
        print("       python yamaha_rs232_controller.py --query <host>")
        print("       python yamaha_rs232_controller.py --monitor <host> [seconds] [state_file]")
        print("       python yamaha_rs232_controller.py --status [state_file]")
        print("\nAvailable commands:")

        categories = YamahaController.get_command_categories()
        for category, commands in categories.items():
            print(f"\n{category}:")
            for cmd in commands:
                print(f"  - {cmd}")

        sys.exit(1)

    host = args[0]
    command_name = args[1]

    try:
        controller = YamahaController(host)
        controller.execute(command_name)
        print(f"[OK] Command '{command_name}' sent successfully")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except ConnectionError as e:
        print(f"Connection error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
