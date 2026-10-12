#!/usr/bin/env python3
"""
Yamaha RX-V2500 to MQTT Bridge
Exposes the receiver to Home Assistant via MQTT Auto-Discovery

Installation on Raspberry Pi:
1. pip3 install paho-mqtt
2. Copy yamaha_rs232_controller.py to same directory
3. Configure MQTT_BROKER, MQTT_USER, MQTT_PASS below (env vars of the
   same name override the defaults)
4. Run: python3 yamaha_mqtt_bridge.py
5. (Optional) Set up as systemd service for auto-start

Note: rxv2500d.py is the more capable event-driven daemon — this simple
bridge is kept as a minimal starting point.

MQTT Topics:
- homeassistant/media_player/yamaha_rxv2500/config (auto-discovery)
- homeassistant/media_player/yamaha_rxv2500/state
- homeassistant/media_player/yamaha_rxv2500/command
- homeassistant/select/yamaha_input/config (input selector)
- homeassistant/select/yamaha_sound_mode/config (sound mode selector)
"""

import json
import os
import time
import logging
from threading import Thread
import paho.mqtt.client as mqtt
from yamaha_rs232_controller import YamahaController

# ============================================================================
# CONFIGURATION - MODIFY THESE (or set env vars of the same name)
# ============================================================================
YAMAHA_HOST = os.environ.get("YAMAHA_HOST", "localhost")  # ser2net host
YAMAHA_PORT = int(os.environ.get("YAMAHA_PORT", "2500"))

MQTT_BROKER = os.environ.get("MQTT_BROKER", "localhost")  # Your MQTT broker IP
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "")    # leave empty if broker has no auth
MQTT_PASS = os.environ.get("MQTT_PASS", "")
MQTT_CLIENT_ID = os.environ.get("MQTT_CLIENT_ID", "yamaha_bridge")

# Home Assistant Discovery Prefix
HA_DISCOVERY_PREFIX = "homeassistant"

# Device info for Home Assistant
DEVICE_NAME = "Yamaha RX-V2500"
DEVICE_ID = "yamaha_rxv2500"

# ============================================================================
# LOGGING
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# INPUT MAPPINGS
# ============================================================================
INPUT_MAP = {
    "Multi-Channel": "input_multi",
    "VCR1": "input_vcr1",
    "DTV": "input_dtv",
    "V-AUX": "input_vaux"
}

# ============================================================================
# SOUND MODE MAPPINGS
# ============================================================================
SOUND_MODE_MAP = {
    "Pure Direct": "pure_direct_on",
    "Straight": "straight",
    "2ch Stereo": "stereo_2ch",
    "7ch Stereo": "stereo_7ch",
    "THX Cinema": "thx_cinema",
    "Pro Logic": "surround_pro_logic",
    "Pro Logic Enhanced": "surround_pro_logic_enhanced",
    "PLIIx Movie": "ext_surround_pliix_movie",
    "PLIIx Music": "ext_surround_pliix_music",
    "Munich": "music_hall_munich",
    "Vienna": "music_hall_vienna",
    "Freiburg": "music_hall_freiburg",
    "Bottom Line": "music_hall_bottom_line",
    "Roxy": "music_hall_roxy",
    "Disco": "entertainment_disco",
    "Game": "entertainment_game",
    "Mono Movie": "entertainment_mono_movie",
    "TV Sports": "entertainment_tv_sports",
    "Pop/Rock": "music_pop_rock",
    "Classical": "music_classical",
    "Spectacle": "movie_spectacle",
    "Sci-Fi": "movie_sci_fi",
    "Adventure": "movie_adventure",
    "General": "movie_general"
}

# ============================================================================
# YAMAHA MQTT BRIDGE
# ============================================================================
class YamahaMQTTBridge:
    def __init__(self):
        self.yamaha = YamahaController(YAMAHA_HOST, YAMAHA_PORT)
        self.mqtt_client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=MQTT_CLIENT_ID)

        # State tracking
        self.power_state = "OFF"
        self.volume_level = 50
        self.muted = False
        self.current_input = "Multi-Channel"
        self.current_sound_mode = "Straight"

        # MQTT setup
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message

        if MQTT_USER and MQTT_PASS:
            self.mqtt_client.username_pw_set(MQTT_USER, MQTT_PASS)

    def on_connect(self, client, userdata, flags, rc):
        """Called when connected to MQTT broker"""
        if rc == 0:
            logger.info("Connected to MQTT broker")
            self.publish_discovery()
            self.subscribe_commands()
            self.publish_state()
        else:
            logger.error(f"Failed to connect to MQTT broker: {rc}")

    def on_message(self, client, userdata, msg):
        """Handle incoming MQTT messages"""
        topic = msg.topic
        payload = msg.payload.decode()

        logger.info(f"Received: {topic} = {payload}")

        try:
            # Main media player commands
            if "media_player" in topic and topic.endswith("/command"):
                self.handle_media_player_command(payload)

            # Input selector
            elif "yamaha_input/set" in topic:
                self.handle_input_command(payload)

            # Sound mode selector
            elif "yamaha_sound_mode/set" in topic:
                self.handle_sound_mode_command(payload)

        except Exception as e:
            logger.error(f"Error handling message: {e}")

    def handle_media_player_command(self, payload):
        """Handle media player commands"""
        command = payload # No longer JSON, payload is the command itself

        if command == "turn_on":
            self.yamaha.execute("power_on")
            self.power_state = "ON"

        elif command == "turn_off":
            self.yamaha.execute("power_off")
            self.power_state = "OFF"

        elif command == "volume_up":
            self.yamaha.execute("vol_up")
            self.volume_level = min(100, self.volume_level + 2)

        elif command == "volume_down":
            self.yamaha.execute("vol_down")
            self.volume_level = max(0, self.volume_level - 2)

        elif command == "mute_on":
            self.yamaha.execute("mute_on")
            self.muted = True

        elif command == "mute_off":
            self.yamaha.execute("mute_off")
            self.muted = False

        self.publish_state()

    def handle_input_command(self, payload):
        """Handle input selection"""
        if payload in INPUT_MAP:
            command = INPUT_MAP[payload]
            self.yamaha.execute(command)
            self.current_input = payload
            self.publish_state()

    def handle_sound_mode_command(self, payload):
        """Handle sound mode selection"""
        if payload in SOUND_MODE_MAP:
            command = SOUND_MODE_MAP[payload]
            self.yamaha.execute(command)
            self.current_sound_mode = payload
            self.publish_state()

    def publish_discovery(self):
        """Publish Home Assistant auto-discovery configs"""

        # Main Media Player
        media_player_config = {
            "name": DEVICE_NAME,
            "unique_id": f"{DEVICE_ID}_media_player",
            "state_topic": f"{HA_DISCOVERY_PREFIX}/media_player/{DEVICE_ID}/state",
            "command_topic": f"{HA_DISCOVERY_PREFIX}/media_player/{DEVICE_ID}/command",
            "state_template": "{{ value_json.state }}",
            "volume_level_state_template": "{{ value_json.volume_level }}",
            "is_volume_muted_state_template": "{{ 'true' if value_json.is_volume_muted else 'false' }}",
            "payload_on": "turn_on",
            "payload_off": "turn_off",
            "payload_volume_up": "volume_up",
            "payload_volume_down": "volume_down",
            "payload_mute": "mute_on",
            "payload_unmute": "mute_off",
            "device": {
                "identifiers": [DEVICE_ID],
                "name": DEVICE_NAME,
                "manufacturer": "Yamaha",
                "model": "RX-V2500"
            }
        }

        # Input Selector
        input_select_config = {
            "name": f"{DEVICE_NAME} Input",
            "unique_id": f"{DEVICE_ID}_input",
            "state_topic": f"{HA_DISCOVERY_PREFIX}/media_player/{DEVICE_ID}/state",
            "command_topic": f"{HA_DISCOVERY_PREFIX}/select/yamaha_input/set",
            "value_template": "{{ value_json.source }}",
            "options": list(INPUT_MAP.keys()),
            "device": {
                "identifiers": [DEVICE_ID],
                "name": DEVICE_NAME
            }
        }

        # Sound Mode Selector
        sound_mode_config = {
            "name": f"{DEVICE_NAME} Sound Mode",
            "unique_id": f"{DEVICE_ID}_sound_mode",
            "state_topic": f"{HA_DISCOVERY_PREFIX}/media_player/{DEVICE_ID}/state",
            "command_topic": f"{HA_DISCOVERY_PREFIX}/select/yamaha_sound_mode/set",
            "value_template": "{{ value_json.sound_mode }}",
            "options": list(SOUND_MODE_MAP.keys()),
            "device": {
                "identifiers": [DEVICE_ID],
                "name": DEVICE_NAME
            }
        }

        # Publish configs
        self.mqtt_client.publish(
            f"{HA_DISCOVERY_PREFIX}/media_player/{DEVICE_ID}/config",
            json.dumps(media_player_config),
            retain=True
        )

        self.mqtt_client.publish(
            f"{HA_DISCOVERY_PREFIX}/select/yamaha_input/config",
            json.dumps(input_select_config),
            retain=True
        )

        self.mqtt_client.publish(
            f"{HA_DISCOVERY_PREFIX}/select/yamaha_sound_mode/config",
            json.dumps(sound_mode_config),
            retain=True
        )

        logger.info("Published discovery configs")

    def subscribe_commands(self):
        """Subscribe to command topics"""
        topics = [
            f"{HA_DISCOVERY_PREFIX}/media_player/{DEVICE_ID}/command",
            f"{HA_DISCOVERY_PREFIX}/select/yamaha_input/set",
            f"{HA_DISCOVERY_PREFIX}/select/yamaha_sound_mode/set"
        ]

        for topic in topics:
            self.mqtt_client.subscribe(topic)
            logger.info(f"Subscribed to {topic}")

    def publish_state(self):
        """Publish current state"""
        state = {
            "state": self.power_state,
            "volume_level": self.volume_level,
            "is_volume_muted": self.muted,
            "source": self.current_input,
            "sound_mode": self.current_sound_mode
        }

        self.mqtt_client.publish(
            f"{HA_DISCOVERY_PREFIX}/media_player/{DEVICE_ID}/state",
            json.dumps(state),
            retain=True
        )

    def run(self):
        """Start the bridge"""
        logger.info(f"Starting Yamaha MQTT Bridge")
        logger.info(f"Yamaha: {YAMAHA_HOST}:{YAMAHA_PORT}")
        logger.info(f"MQTT: {MQTT_BROKER}:{MQTT_PORT}")

        self.mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
        self.mqtt_client.loop_forever()

# ============================================================================
# MAIN
# ============================================================================
def main():
    bridge = YamahaMQTTBridge()

    try:
        bridge.run()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")

if __name__ == "__main__":
    main()
