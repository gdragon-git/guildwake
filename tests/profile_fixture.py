"""Synthetic local policy only; imports never contact Discord/AMP/WOL."""
import json
from pathlib import Path
from discord_amp.config import configure, parse

RAW = json.loads((Path(__file__).resolve().parents[1] / 'examples/profile.example.json').read_bytes())
PROFILE = configure(parse(RAW))
OWNER, GUILD, CHANNEL, APPLICATION, ROLE = (getattr(PROFILE, key) for key in ('owner', 'guild', 'channel', 'application', 'role'))
HOST, GAME, INSTANCE, INSTANCE_ID = PROFILE.host, PROFILE.game, PROFILE.selected, PROFILE.selected_id
INSTANCES, STORAGE_UUID = PROFILE.instances, PROFILE.storage_uuid
COMMANDS = PROFILE.commands
