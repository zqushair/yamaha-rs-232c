#!/usr/bin/env python3
"""
geekmagic_display — push Yamaha RX-V2500 state to a GeekMagic SmallTV display.

Consumes the rxv2500d MQTT state topics, renders a dense 240x240 dashboard
(clock, input, volume, DSP mode, status chips) with Pillow, and pushes it to
a GeekMagic SmallTV Pro/Ultra over the stock firmware's HTTP API:

  GET  /v.json                          identify firmware profile
  POST /doUpload?dir=/image/           multipart upload (field "file")
  GET  /set?theme=4                     Pro: custom image (picture album) theme
  GET  /set?theme=3                     Ultra: custom image theme
  GET  /set?img=/image/<file>           Ultra: select image directly
  GET  /filelist?dir=/image/            list album files (Pro album management)
  GET  /delete?file=<path>              delete an album file
  GET  /set?i_i=999&autoplay=0          Pro: album settings (manual advance)

Single-page mode (PAGES=1, the default): one dashboard image with everything
on it (clock, volume, DSP mode, status chips).  The stock firmware only
re-decodes an image when the theme is (re-)entered — replacing the file in
place is NOT refreshed on-screen — so the daemon re-asserts the theme after
every push.  That is safe with one image (nothing to scroll to) and gives
reliable live updates.

Config: KEY=VALUE file + GEEKMAGIC_* env overrides (same convention as
rxv2500d.py).
"""

import argparse
import http.client
import json
import logging
import os
import re
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from io import BytesIO

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    Image = None

LOG = logging.getLogger('geekmagic_display')

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG = {
    'MQTT_HOST': 'localhost',
    'MQTT_PORT': '1883',
    'MQTT_USER': '',
    'MQTT_PASS': '',
    'CLIENT_ID': 'geekmagic_display',
    'ROOT': 'rxv2500',
    'DISPLAY_HOST': '',             # required — IP of the GeekMagic display
    'DISPLAY_PORT': '80',
    'DEBOUNCE_MS': '400',           # coalesce bursts of state changes
    'PUSH_MIN_INTERVAL': '0.6',     # min seconds between uploads
    'WATCHDOG_INTERVAL': '60',      # re-assert theme/image this often
    'BRIGHTNESS': '',               # optional, set on start (0-100)
    'STANDBY_MODE': 'clock',        # 'clock' = show clock on standby, 'card' = always show card
    'BACKUP_DIR': '/var/lib/geekmagic_display/album_backup',
    'PAGES': '1',                    # comma-separated page IDs (1 = dashboard)
    'PAGE': '1',                    # initial page (1-based)
    'REFRESH_INTERVAL': '3',        # single-page: slideshow tick (s) that re-reads the file (self-refresh)
    'BUTTON_MODE': 'native',        # 'native' = stock button cycles album images, 'poll' = detect theme drift, 'off'
    'BUTTON_POLL_INTERVAL': '0.5',  # seconds between app.json polls (poll mode)
    'FONT_BOLD': '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    'FONT_REGULAR': '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    'JPEG_QUALITY': '85',
    'LOG_LEVEL': 'INFO',
}

TRUE_VALUES = {'ON', 'TRUE', '1', 'YES'}

FONT_CANDIDATES = (
    '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
    '/usr/share/fonts/truetype/freefont/FreeSansBold.ttf',
)

IMAGE_SIZE = 240
UPLOAD_FILENAME = 'rxv2500.jpg'


def page_filename(page):
    """Album filename for a page number."""
    return 'rxv2500_p%d.jpg' % page

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

BG = (11, 13, 18)
CARD_BG = (22, 25, 34)
ACCENT = (64, 156, 255)
TEXT_PRIMARY = (240, 242, 248)
TEXT_SECONDARY = (140, 148, 165)
TEXT_DIM = (80, 86, 100)
MUTE_RED = (220, 60, 60)
BAR_BG = (40, 44, 56)
BAR_FILL = (64, 156, 255)
STANDBY_BG = (8, 9, 12)


# ---------------------------------------------------------------------------
# Config loading (same convention as rxv2500d.py)
# ---------------------------------------------------------------------------

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
                    # Strip inline comments (a '#' after whitespace)
                    val = re.split(r'\s+#', val, 1)[0]
                    cfg[key.strip().upper()] = val.strip()
    for key in list(cfg):                       # GEEKMAGIC_* env overrides
        env = os.environ.get('GEEKMAGIC_' + key)
        if env is not None:
            cfg[key] = env
    return cfg


def cfg_bool(cfg, key):
    return cfg.get(key, '').strip().upper() in TRUE_VALUES


def _is_power_on(power):
    """Check if power state indicates the receiver is on.

    Handles both string ('ON'/'OFF') and bool values from MQTT.
    """
    if power is None:
        return True  # default to on if unknown
    if isinstance(power, bool):
        return power
    return power.upper() in ('ON', 'TRUE', '1', 'YES')


# ---------------------------------------------------------------------------
# Font loading
# ---------------------------------------------------------------------------

def load_font(path, size):
    """Load a TTF, falling back to common system fonts, then PIL default."""
    for candidate in [path] + list(FONT_CANDIDATES):
        if candidate and os.path.exists(candidate):
            try:
                return ImageFont.truetype(candidate, size)
            except OSError:
                continue
    try:
        return ImageFont.load_default(size=size)   # Pillow >= 10.1
    except TypeError:
        return ImageFont.load_default()


# ---------------------------------------------------------------------------
# Card renderer
# ---------------------------------------------------------------------------

def _rounded_rect(draw, xy, radius, fill):
    """Draw a rounded rectangle."""
    draw.rounded_rectangle(xy, radius=radius, fill=fill)


def _text(draw, xy, text, font, fill, anchor=None):
    draw.text(xy, text, font=font, fill=fill, anchor=anchor)


def _text_size(draw, text, font):
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0], bbox[3] - bbox[1]


def _fit_font(draw, text, max_width, base_size, min_size=11):
    """Return a font small enough that text fits within max_width."""
    size = base_size
    while size > min_size:
        font = load_font(None, size)
        w, _ = _text_size(draw, text, font)
        if w <= max_width:
            return font
        size -= 1
    return load_font(None, min_size)


def _wrap_chips(d, chips, font, margin=10, chip_gap=6):
    """Wrap chips into centered rows. Returns (rows, total_widths)."""
    sized = []
    for text, color in chips:
        tw, _ = _text_size(d, text, font)
        sized.append((text, color, tw + 16))

    rows = [[]]
    row_w = 0
    for text, color, cw in sized:
        w_needed = cw + (chip_gap if rows[-1] else 0)
        if rows[-1] and row_w + w_needed > IMAGE_SIZE - 2 * margin:
            rows.append([])
            row_w = 0
            w_needed = cw
        rows[-1].append((text, color, cw))
        row_w += w_needed
    return rows


def _draw_chips(d, chips, y0, font, chip_h=20, row_gap=5, chip_gap=6,
                margin=10, max_rows=2):
    """Draw centered, shrinking chips so they fit in max_rows. Returns y below."""
    if not chips:
        return y0
    # Shrink the font until the chips wrap into at most max_rows rows
    size = font.size if hasattr(font, 'size') else 12
    while size > 9:
        probe = load_font(None, size)
        if len(_wrap_chips(d, chips, probe, margin, chip_gap)) <= max_rows:
            font = probe
            break
        size -= 1
    else:
        font = load_font(None, 9)

    rows = _wrap_chips(d, chips, font, margin, chip_gap)

    y = y0
    for row in rows:
        total_w = sum(cw for _, _, cw in row) + chip_gap * (len(row) - 1)
        x = (IMAGE_SIZE - total_w) // 2
        for text, color, cw in row:
            _rounded_rect(d, (x, y, x + cw, y + chip_h), 5, color)
            chip_text = BG if color == ACCENT else TEXT_PRIMARY
            _text(d, (x + 8, y + (chip_h - _text_size(d, text, font)[1]) // 2),
                  text, font, chip_text)
            x += cw + chip_gap
        y += chip_h + row_gap
    return y - row_gap


def _render_dashboard(state, quality=85):
    """Single dense page: clock, volume hero + bar, DSP mode, status chips."""
    img = Image.new('RGB', (IMAGE_SIZE, IMAGE_SIZE), BG)
    d = ImageDraw.Draw(img)

    font_time = load_font(None, 50)
    font_date = load_font(None, 13)
    font_hero = load_font(None, 36)
    font_unit = load_font(None, 12)
    font_dsp = load_font(None, 16)
    font_chip = load_font(None, 12)
    font_link = load_font(None, 11)

    power_on = _is_power_on(state.get('power'))
    input_name = state.get('input', '')
    volume_db = state.get('volume_db')
    mute = state.get('mute')
    sound_program = state.get('sound_program', '') or ''
    straight = state.get('straight')
    pure_direct = state.get('pure_direct')
    ext_surround = state.get('ext_surround', '') or ''
    night_mode = state.get('night_mode', '') or ''
    speaker_b = state.get('speaker_b')
    sleep = state.get('sleep', '') or ''
    availability = (state.get('availability', '') or '').upper()

    now = time.localtime()
    time_str = time.strftime('%H:%M', now)
    date_str = time.strftime('%a %b %d', now)

    # ---- header: input chip (left), mute chip / link dot (right) ----
    if input_name:
        tw, th = _text_size(d, input_name, font_chip)
        _rounded_rect(d, (10, 10, 10 + tw + 18, 10 + th + 10), 5, CARD_BG)
        _text(d, (19, 15), input_name, font_chip, ACCENT)

    if mute:
        mw, mh = _text_size(d, 'MUTE', font_chip)
        x1 = IMAGE_SIZE - 10
        _rounded_rect(d, (x1 - mw - 16, 10, x1, 10 + mh + 10), 5, MUTE_RED)
        _text(d, (x1 - mw - 8, 15), 'MUTE', font_chip, (255, 255, 255))
    elif availability:
        dot_color = (60, 190, 110) if availability == 'ONLINE' else MUTE_RED
        d.ellipse((IMAGE_SIZE - 66, 16, IMAGE_SIZE - 58, 24), fill=dot_color)
        _text(d, (IMAGE_SIZE - 52, 13), availability, font_link, TEXT_DIM)

    # ---- clock ----
    _text(d, (IMAGE_SIZE // 2, 62), time_str, font_time,
          TEXT_PRIMARY, anchor='mm')
    _text(d, (IMAGE_SIZE // 2, 94), date_str, font_date,
          TEXT_SECONDARY, anchor='mm')

    if not power_on:
        _text(d, (IMAGE_SIZE // 2, 145), 'STANDBY', font_hero,
              TEXT_DIM, anchor='mm')
    else:
        # ---- volume hero + bar ----
        if volume_db is not None:
            vol_text = '%.1f' % volume_db
            vw, vh = _text_size(d, vol_text, font_hero)
            uw, uh = _text_size(d, 'dB', font_unit)
            total_w = vw + 6 + uw
            x = (IMAGE_SIZE - total_w) // 2
            vol_color = MUTE_RED if mute else TEXT_PRIMARY
            _text(d, (x, 116), vol_text, font_hero, vol_color)
            _text(d, (x + vw + 6, 116 + vh - uh - 3), 'dB', font_unit,
                  TEXT_SECONDARY)

            bar_x, bar_y = 20, 162
            bar_w, bar_h = IMAGE_SIZE - 40, 8
            _rounded_rect(d, (bar_x, bar_y, bar_x + bar_w, bar_y + bar_h),
                          4, BAR_BG)
            frac = max(0.0, min(1.0, (volume_db + 80.0) / 94.0))
            fill_w = int(bar_w * frac)
            if fill_w > 0:
                _rounded_rect(d, (bar_x, bar_y,
                                   bar_x + fill_w, bar_y + bar_h),
                              4, MUTE_RED if mute else BAR_FILL)
        else:
            _text(d, (IMAGE_SIZE // 2, 140), '--.- dB', font_hero,
                  TEXT_DIM, anchor='mm')

        # ---- DSP mode ----
        if sound_program:
            prog_font = _fit_font(d, sound_program, IMAGE_SIZE - 24, 16)
            _text(d, (IMAGE_SIZE // 2, 181), sound_program, prog_font,
                  ACCENT, anchor='mm')

        # ---- status chips ----
        chips = []
        if straight:
            chips.append(('STRAIGHT', ACCENT))
        if pure_direct:
            chips.append(('PURE DIRECT', ACCENT))
        if ext_surround and ext_surround != 'OFF':
            chips.append((ext_surround, CARD_BG))
        if night_mode and night_mode != 'OFF':
            chips.append(('NIGHT', CARD_BG))
        if speaker_b:
            chips.append(('SPK B', CARD_BG))
        if sleep and sleep.upper() not in ('OFF', '0'):
            chips.append(('SLEEP %s' % sleep, CARD_BG))
        _draw_chips(d, chips, 194, font_chip)

    buf = BytesIO()
    img.save(buf, 'JPEG', quality=quality)
    return buf.getvalue()


_PAGE_RENDERERS = {
    1: _render_dashboard,
}


def render_page(state, page, total, quality=85):
    """Render a specific page. Returns JPEG bytes."""
    renderer = _PAGE_RENDERERS.get(page, _render_dashboard)
    img = renderer(state, quality)
    return img


def render_card(state, quality=85):
    """Render the dashboard card."""
    return render_page(state, 1, 1, quality)


# ---------------------------------------------------------------------------
# GeekMagic device HTTP client
# ---------------------------------------------------------------------------

class GeekMagicError(Exception):
    pass


class GeekMagicDevice:
    """Minimal HTTP client for GeekMagic stock firmware.

    Supports the Pro (picture-album), Ultra (direct image), and SD_PRO
    (photo slideshow) firmware profiles.  The legacy weather-clock
    firmware is detected but not supported.
    """

    def __init__(self, host, port=80, timeout=5):
        self.base = 'http://%s:%s' % (host, port)
        self.timeout = timeout
        self.profile = None      # 'pro' | 'ultra' | 'sdpro'
        self.model = None
        self.firmware = None

    # -- low level ----------------------------------------------------------

    def _get(self, path):
        url = self.base + path
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()

    def _get_json(self, path):
        return json.loads(self._get(path).decode('utf-8', 'replace'))

    def _get_checked(self, path, action):
        """GET and require an OK answer (stock firmware answers OK or FAIL)."""
        text = self._get(path).decode('utf-8', 'replace').strip()
        if text.upper() == 'FAIL':
            raise GeekMagicError('%s rejected: %s' % (action, text))
        return text

    def _post_file(self, path, field_name, data, filename, content_type):
        """POST a multipart file upload.

        The stock firmware frequently sends a malformed response (duplicate
        Content-Length or data after Connection: close) after a successful
        upload.  We tolerate that here and let the caller verify.
        """
        boundary = '----geekmagic%d' % int(time.time() * 1000)
        body = b''
        body += ('--%s\r\n' % boundary).encode()
        body += ('Content-Disposition: form-data; name="%s"; '
                 'filename="%s"\r\n' % (field_name, filename)).encode()
        body += ('Content-Type: %s\r\n\r\n' % content_type).encode()
        body += data
        body += ('\r\n--%s--\r\n' % boundary).encode()

        url = self.base + path
        req = urllib.request.Request(url, data=body, method='POST')
        req.add_header('Content-Type',
                       'multipart/form-data; boundary=%s' % boundary)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except (urllib.error.URLError, http.client.HTTPException,
                ConnectionResetError, OSError) as exc:
            # Malformed firmware response — upload may have succeeded.
            LOG.debug('upload response error (tolerated): %s', exc)

    # -- profile detection --------------------------------------------------

    def probe(self):
        """Detect the firmware profile. Returns 'pro', 'ultra', or 'sdpro'."""
        # Try /v.json first (both Pro and Ultra)
        try:
            data = self._get_json('/v.json')
            model = str(data.get('m', ''))
            self.firmware = str(data.get('v', ''))
            model_key = model.lower()
            if 'pro' in model_key:
                self.profile = 'pro'
            elif 'ultra' in model_key:
                self.profile = 'ultra'
            else:
                self.profile = 'pro'   # default guess
            self.model = model
            LOG.info('detected %s (firmware %s) via /v.json',
                     model, self.firmware)
            return self.profile
        except Exception as exc:
            LOG.debug('/v.json not available: %s', exc)

        # Pro fallback: /.sys/app.json
        try:
            self._get_json('/.sys/app.json')
            self.profile = 'pro'
            self.model = 'SmallTV Pro'
            LOG.info('detected SmallTV Pro via /.sys/app.json')
            return self.profile
        except Exception as exc:
            LOG.debug('/.sys/app.json not available: %s', exc)

        # Ultra fallback: /app.json
        try:
            self._get_json('/app.json')
            self.profile = 'ultra'
            self.model = 'SmallTV Ultra'
            LOG.info('detected SmallTV Ultra via /app.json')
            return self.profile
        except Exception as exc:
            LOG.debug('/app.json not available: %s', exc)

        # SD_PRO community firmware: /config
        try:
            self._get_json('/config')
            self.profile = 'sdpro'
            self.model = 'SD_PRO'
            LOG.info('detected SD_PRO community firmware via /config')
            return self.profile
        except Exception as exc:
            LOG.debug('/config not available: %s', exc)

        raise GeekMagicError(
            'could not detect firmware profile — is this a GeekMagic device?')

    # -- album management (Pro / Ultra) -------------------------------------

    def _list_album_files(self):
        """List files in /image/ via the stock filelist HTML page."""
        html = self._get('/filelist?dir=/image/').decode('utf-8', 'replace')
        pattern = re.compile(
            r"<a href='(?P<path>[^']+)'>(?P<name>[^<]+)</a>"
            r'</td><td>(?P<size>[^<]+)</td>'
        )
        return [(m.group('name'), m.group('path'))
                for m in pattern.finditer(html)]

    def _delete_file(self, path):
        self._get_checked('/delete?file=%s' % path, 'delete %s' % path)

    def keep_only_images(self, filenames):
        """Delete every album file except the given names (Pro/Ultra)."""
        keep = set(filenames)
        for name, path in self._list_album_files():
            if name not in keep:
                LOG.info('deleting album file %s', name)
                self._delete_file(path)

    # Backward-compatible single-file variant
    def keep_only_image(self, filename):
        self.keep_only_images([filename])

    def backup_album(self, backup_dir):
        """Download all album files to backup_dir, then delete all except
        our page images.

        Returns the number of files backed up.
        """
        os.makedirs(backup_dir, exist_ok=True)
        files = self._list_album_files()
        keep = {page_filename(p) for p in range(1, 5)}

        # Download all files first — never delete before backup succeeds
        backed_up = 0
        for name, path in files:
            if name in keep:
                continue
            data = self._get(path)
            backup_path = os.path.join(backup_dir, name)
            with open(backup_path, 'wb') as f:
                f.write(data)
            backed_up += 1
            LOG.info('backed up %s (%d bytes)', name, len(data))

        # Now delete all except our page files (boot.gif included — it
        # shows in the album and makes the button cycle to it)
        for name, path in files:
            if name in keep:
                continue
            LOG.info('deleting album file %s', name)
            self._delete_file(path)

        return backed_up

    # -- upload + display ---------------------------------------------------

    def upload(self, filename, data):
        """Upload an image to the device."""
        if self.profile == 'sdpro':
            self._post_file('/photo/upload', 'file', data, filename,
                            'image/jpeg')
        else:
            self._post_file('/doUpload?dir=/image/', 'file', data, filename,
                            'image/jpeg')
        LOG.debug('uploaded %s (%d bytes)', filename, len(data))

    def set_image(self, filename, interval=999, autoplay=0):
        """Make the uploaded image the displayed one.

        Pro: the firmware only re-decodes an image when the album advances
        (slideshow tick or touch button) or the theme is re-entered —
        replacing the file on flash is NOT redrawn on its own.  With a
        single album image, slideshow mode becomes a self-refresh: every
        `interval` seconds the album re-reads the same file, so uploads
        appear within `interval` seconds without disturbing position.
        Multi-page callers keep autoplay=0 (manual button advance).
        """
        if self.profile == 'pro':
            self._get_checked(
                '/set?i_i=%d&gif_loop=1&autoplay=%d' % (interval, autoplay),
                'album display')
            self._get_checked('/set?theme=4', 'theme 4')
        elif self.profile == 'ultra':
            # Ultra: direct image selection
            self._get_checked('/set?theme=3', 'theme 3')
            try:
                self._get_checked('/set?img=/image/%s' % filename,
                                  'image select')
            except GeekMagicError:
                # Some Pro firmwares answer FAIL to /set?img= even in custom
                # image mode, where uploading to the same filename already
                # refreshes the display.  Treat as success.
                LOG.debug('/set?img= answered FAIL — upload likely refreshed '
                          'the display')
        elif self.profile == 'sdpro':
            self._set_sdpro_exclusive(filename)

    def _set_sdpro_exclusive(self, filename):
        """Make one SD_PRO photo and the Photo theme active."""
        # Enable only our photo
        data = self._get_json('/photo/list')
        for item in data.get('files', []):
            name = item.get('name', '')
            state = 1 if name == filename else 0
            self._get_checked('/photo/toggle?name=%s&state=%d' % (name, state),
                              'photo toggle %s' % name)
        # Enable only the Photo theme (id 2)
        themes = self._get_json('/theme/list')
        for theme in themes.get('themes', []):
            tid = theme.get('id', 0)
            state = 1 if tid == 2 else 0
            self._get_checked('/theme/toggle?id=%d&state=%d' % (tid, state),
                              'theme toggle %d' % tid)
        self._get_checked('/photo/interval?val=1', 'photo interval')
        self._get_checked('/api/set?key=theme&value=2', 'theme 2')

    def get_state(self):
        """Read back device state (theme, brightness, current image)."""
        if self.profile == 'sdpro':
            data = self._get_json('/config')
            return {'theme': data.get('theme'),
                    'brightness': data.get('lcd_brightness')}
        for path in ('/.sys/app.json', '/app.json'):
            try:
                data = self._get_json(path)
                return {'theme': data.get('theme'),
                        'brightness': data.get('brt'),
                        'image': data.get('img')}
            except Exception:
                continue
        return {}

    def set_brightness(self, value):
        """Set display brightness (0-100)."""
        value = max(0, min(100, int(value)))
        if self.profile == 'sdpro':
            self._get_checked('/api/set?key=lcd_brightness&value=%d' % value,
                              'brightness')
        else:
            self._get_checked('/set?brt=%d' % value, 'brightness')


# ---------------------------------------------------------------------------
# Daemon
# ---------------------------------------------------------------------------

class Daemon:
    def __init__(self, cfg):
        self.cfg = cfg
        self.root = cfg['ROOT'].strip('/')
        self.state = {}
        self._state_lock = threading.Lock()
        self._dirty = threading.Event()
        self._stop = threading.Event()
        self._last_push = 0.0
        self._last_images = {}     # page -> last pushed JPEG bytes
        self._theme_ok = False     # theme/album params asserted for this run
        self._album_pinned = False  # album pruned to page files once

        # Page rotation
        self.pages = [int(p) for p in cfg.get('PAGES', '1,2,3,4').split(',')
                       if p.strip()]
        if not self.pages:
            self.pages = [1, 2, 3, 4]
        self.total_pages = len(self.pages)
        self.current_page = int(cfg.get('PAGE', '1'))
        if self.current_page not in self.pages:
            self.current_page = self.pages[0]
        self._page_lock = threading.Lock()
        # Single-page self-refresh: album re-reads the same file every N s
        try:
            self._single_interval = max(1, int(cfg.get('REFRESH_INTERVAL', '3')))
        except ValueError:
            self._single_interval = 3

        self.device = GeekMagicDevice(
            cfg['DISPLAY_HOST'], int(cfg['DISPLAY_PORT']))

        self.mqtt_client = self._make_mqtt_client()

    # -- MQTT ---------------------------------------------------------------

    def _make_mqtt_client(self):
        import paho.mqtt.client as mqtt
        try:
            from paho.mqtt.enums import CallbackAPIVersion
            client = mqtt.Client(CallbackAPIVersion.VERSION2,
                                 client_id=self.cfg['CLIENT_ID'])
        except (ImportError, AttributeError):
            client = mqtt.Client(client_id=self.cfg['CLIENT_ID'])
        if self.cfg['MQTT_USER']:
            client.username_pw_set(self.cfg['MQTT_USER'], self.cfg['MQTT_PASS'])
        client.on_connect = self._mqtt_on_connect
        client.on_disconnect = self._mqtt_on_disconnect
        client.on_message = self._mqtt_on_message
        return client

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
        client.subscribe('%s/state/#' % self.root, qos=1)
        client.subscribe('%s/availability' % self.root, qos=1)

    def _mqtt_on_disconnect(self, client, userdata, *args):
        LOG.warning('MQTT disconnected')

    def _mqtt_on_message(self, client, userdata, msg):
        topic = msg.topic
        payload = msg.payload.decode('utf-8', 'replace').strip()

        if topic == '%s/availability' % self.root:
            if payload == 'online':
                LOG.info('rxv2500d is online — will re-push on next change')
            with self._state_lock:
                self.state['availability'] = payload
            self._dirty.set()
            return

        prefix = '%s/state/' % self.root
        if not topic.startswith(prefix):
            return
        field = topic[len(prefix):]

        # Convert payloads to appropriate types
        value = self._convert_value(field, payload)

        with self._state_lock:
            self.state[field] = value
        self._dirty.set()
        LOG.debug('state %s=%r', field, value)

    @staticmethod
    def _convert_value(field, payload):
        """Convert MQTT string payloads to appropriate Python types."""
        if field in ('volume_db', 'volume'):
            try:
                return float(payload)
            except (ValueError, TypeError):
                return payload
        if field in ('mute', 'straight', 'pure_direct', 'power', 'speaker_b'):
            return payload.upper() in ('ON', 'TRUE', '1', 'YES')
        return payload

    # -- push loop ----------------------------------------------------------

    def _assert_theme(self):
        """Re-enter the image theme/album config (forces a decode).

        Single-page mode enables the slideshow tick so the album re-reads
        the same file periodically (self-refresh); multi-page keeps manual
        button advance.
        """
        if self.total_pages == 1:
            self.device.set_image(page_filename(self.pages[0]),
                                  interval=self._single_interval,
                                  autoplay=1)
        else:
            self.device.set_image(page_filename(self.pages[0]))
        self._theme_ok = True

    def _push(self):
        """Render every configured page and upload only the changed ones.

        All pages live in the album simultaneously — the stock firmware's
        touch button cycles them natively, so the daemon never selects which
        page is on screen; it just keeps them all fresh.

        In STANDBY_MODE=clock, switches to the clock theme when the receiver
        is off instead of pushing cards.
        """
        with self._state_lock:
            state = dict(self.state)

        power_on = _is_power_on(state.get('power'))

        # Standby: switch to clock theme if configured
        if not power_on and self.cfg.get('STANDBY_MODE', 'clock') == 'clock':
            try:
                self.device._get_checked('/set?theme=1', 'theme 1')
                LOG.info('standby — switched to clock theme')
            except Exception as exc:
                LOG.warning('standby theme switch failed: %s', exc)
            self._theme_ok = False      # re-assert card theme on wake
            return

        quality = int(self.cfg.get('JPEG_QUALITY', 85))
        rendered = {}
        changed = []
        for page in self.pages:
            image = render_page(state, page, self.total_pages, quality)
            rendered[page] = image
            if self._last_images.get(page) != image:
                changed.append(page)

        if not changed and self._theme_ok:
            LOG.debug('images unchanged — skipping push')
            return

        # Throttle
        now = time.monotonic()
        min_interval = float(self.cfg.get('PUSH_MIN_INTERVAL', 1.5))
        elapsed = now - self._last_push
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)

        try:
            for page in changed:
                image = rendered[page]
                self.device.upload(page_filename(page), image)
                self._last_images[page] = image
                LOG.debug('uploaded page %d (%d bytes)', page, len(image))

            # Single-page mode: the firmware never redraws a file replaced
            # in place, and a theme re-assert while already on theme 4 is a
            # no-op (verified) — the only things that re-decode are album
            # advances (slideshow tick / touch button) or a theme entry.
            # So configure the single-image album as a slideshow: every
            # interval seconds it re-reads the same file from flash, giving
            # self-refreshing live updates within `interval` seconds.
            # Position cannot drift (one image) and the touch button stays
            # harmless.  Multi-page mode must NOT do this (it would fight
            # the button-selected page) — it only asserts on wake/drift.
            if not self._theme_ok:
                if self.total_pages == 1:
                    LOG.info('theme asserted (single image, slideshow '
                             'refresh every %ds)', self._single_interval)
                else:
                    LOG.info('theme asserted (album, autoplay off)')
                self._assert_theme()

            if changed and not self._album_pinned:
                names = [page_filename(p) for p in self.pages]
                self.device.keep_only_images(names)
                self._album_pinned = True

            self._last_push = time.monotonic()
            if changed:
                LOG.info('pushed pages %s', ','.join(str(p) for p in changed))
        except Exception as exc:
            LOG.warning('push failed: %s', exc)

    def _advance_page(self):
        """Move to the next page in the rotation (poll-mode button)."""
        with self._page_lock:
            idx = self.pages.index(self.current_page)
            self.current_page = self.pages[(idx + 1) % len(self.pages)]
            new_page = self.current_page
        self._last_images.clear()   # force re-render
        self._dirty.set()
        LOG.info('advanced to page %d', new_page)

    def _button_watch(self):
        """Optional theme-drift button detection.

        BUTTON_MODE=native (default on the Pro): the stock firmware cycles
        album images with the touch button — no detection needed, this
        thread exits immediately.

        BUTTON_MODE=poll: fast-poll app.json; a theme change away from the
        card theme counts as a press and advances the daemon-side page.
        """
        interval = float(self.cfg.get('BUTTON_POLL_INTERVAL', '0.5'))
        mode = self.cfg.get('BUTTON_MODE', 'native')
        if mode != 'poll':
            LOG.info('button mode: %s (stock button cycles album natively '
                     'if native)', mode)
            return
        expected_theme = 4 if self.device.profile == 'pro' else 3
        while not self._stop.wait(interval):
            try:
                with self._state_lock:
                    state = dict(self.state)
                if not _is_power_on(state.get('power')):
                    continue
                dev_state = self.device.get_state()
                if not dev_state:
                    continue
                theme = dev_state.get('theme')
                try:
                    theme_int = int(theme) if theme is not None else None
                except (ValueError, TypeError):
                    theme_int = None
                if theme_int is not None and theme_int != expected_theme:
                    LOG.info('button press detected (theme drifted to %s) — '
                             'advancing page', theme)
                    self._advance_page()
            except Exception as exc:
                LOG.debug('button watch error: %s', exc)

    def _watchdog(self):
        """Periodically re-assert theme/image (device may reboot into a stock
        app) and push the current card."""
        interval = float(self.cfg.get('WATCHDOG_INTERVAL', 60))
        while not self._stop.wait(interval):
            try:
                with self._state_lock:
                    state = dict(self.state)
                power_on = _is_power_on(state.get('power'))

                dev_state = self.device.get_state()
                if dev_state:
                    LOG.debug('device state: %s', dev_state)
                    theme = dev_state.get('theme')
                    try:
                        theme_int = int(theme) if theme is not None else None
                    except (ValueError, TypeError):
                        theme_int = None

                    if power_on:
                        # Receiver on: re-assert card theme
                        expected = 4 if self.device.profile == 'pro' else 3
                        if theme_int != expected:
                            LOG.info('device theme drifted to %s — '
                                     're-asserting theme %d', theme, expected)
                            self._assert_theme()
                    else:
                        # Receiver off: re-assert clock theme if configured
                        if self.cfg.get('STANDBY_MODE', 'clock') == 'clock' \
                                and theme_int != 1:
                            LOG.info('device theme drifted to %s — '
                                     're-asserting theme 1 (clock)', theme)
                            self.device._get_checked('/set?theme=1', 'theme 1')

                # Re-push all pages if powered on
                if power_on:
                    self._last_images.clear()   # force re-render
                    self._dirty.set()
            except Exception as exc:
                LOG.warning('watchdog: %s', exc)

    def _debounce_loop(self):
        """Wait for state changes, debounce, then push."""
        debounce_s = float(self.cfg.get('DEBOUNCE_MS', 700)) / 1000.0
        while not self._stop.is_set():
            self._dirty.wait(1.0)
            if self._stop.is_set():
                break
            if not self._dirty.is_set():
                continue
            # Wait for the debounce window to expire
            time.sleep(debounce_s)
            self._dirty.clear()
            if self._stop.is_set():
                break
            self._push()

    # -- lifecycle ----------------------------------------------------------

    def start(self):
        # Probe the display
        LOG.info('probing %s:%s ...', self.cfg['DISPLAY_HOST'],
                 self.cfg['DISPLAY_PORT'])
        self.device.probe()

        # Optional brightness
        brightness = self.cfg.get('BRIGHTNESS', '')
        if brightness:
            try:
                self.device.set_brightness(int(brightness))
                LOG.info('brightness set to %s', brightness)
            except Exception as exc:
                LOG.warning('could not set brightness: %s', exc)

        # Connect MQTT
        host, port = self.cfg['MQTT_HOST'], int(self.cfg['MQTT_PORT'])
        LOG.info('connecting to MQTT broker %s:%s', host, port)
        self.mqtt_client.connect_async(host, port, keepalive=60)
        self.mqtt_client.loop_start()

        # Start threads
        threading.Thread(target=self._debounce_loop, name='debounce',
                         daemon=True).start()
        threading.Thread(target=self._watchdog, name='watchdog',
                         daemon=True).start()
        threading.Thread(target=self._button_watch, name='button-watch',
                         daemon=True).start()

    def stop(self):
        LOG.info('shutting down')
        self._stop.set()
        self._dirty.set()
        try:
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description='Push Yamaha RX-V2500 state to a GeekMagic SmallTV display')
    ap.add_argument('--config', default='/etc/geekmagic_display.conf',
                    help='KEY=VALUE config file (optional)')
    ap.add_argument('--probe', action='store_true',
                    help='probe the display and exit')
    ap.add_argument('--test-card', action='store_true',
                    help='render a test card, push it, and exit')
    ap.add_argument('--backup-album', action='store_true',
                    help='back up the album, then pin it to our card, and exit')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    cfg = load_config(args.config)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose
        else getattr(logging, cfg['LOG_LEVEL'].upper(), logging.INFO),
        format='%(asctime)s %(levelname)-7s %(name)s: %(message)s')

    if Image is None:
        LOG.error('Pillow is required — pip3 install Pillow')
        sys.exit(1)

    if not cfg['DISPLAY_HOST']:
        LOG.error('DISPLAY_HOST is required (set it in the config file or '
                  'via GEEKMAGIC_DISPLAY_HOST)')
        sys.exit(1)

    device = GeekMagicDevice(cfg['DISPLAY_HOST'], int(cfg['DISPLAY_PORT']))

    if args.probe:
        profile = device.probe()
        print('profile: %s' % profile)
        print('model:   %s' % device.model)
        if device.firmware:
            print('firmware: %s' % device.firmware)
        try:
            state = device.get_state()
            print('state:   %s' % json.dumps(state))
        except Exception as exc:
            print('state:   unavailable (%s)' % exc)
        return

    if args.test_card:
        device.probe()
        test_state = {
            'power': True,
            'input': 'DVD',
            'volume_db': -35.5,
            'mute': False,
            'sound_program': 'SPECTACLE',
            'straight': False,
            'pure_direct': False,
            'ext_surround': 'PLIIx_MOVIE',
            'night_mode': 'OFF',
        }
        quality = int(cfg.get('JPEG_QUALITY', 85))
        image = render_page(test_state, 1, 1, quality)
        device.upload(page_filename(1), image)
        print('pushed page 1 (%d bytes)' % len(image))
        device.set_image(page_filename(1), interval=3, autoplay=1)
        if device.profile in ('pro', 'ultra'):
            device.keep_only_images([page_filename(1)])
        print('pushed to %s (profile %s)' % (cfg['DISPLAY_HOST'],
                                              device.profile))
        return

    if args.backup_album:
        device.probe()
        backup_dir = cfg.get('BACKUP_DIR', '/var/lib/geekmagic_display/album_backup')
        print('backing up album to %s ...' % backup_dir)
        count = device.backup_album(backup_dir)
        print('backed up %d files — album pinned to page images '
              '(rxv2500_p1..p4)' % count)
        return

    daemon = Daemon(cfg)

    def shutdown(signum, frame):
        LOG.info('signal %s', signal.Signals(signum).name)
        threading.Thread(target=daemon.stop, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    daemon.start()
    while not daemon._stop.is_set():
        time.sleep(0.5)
    time.sleep(1.0)


if __name__ == '__main__':
    main()
