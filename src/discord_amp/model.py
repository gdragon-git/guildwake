"""Closed command vocabulary and exact identities for the approved first host."""
from .config import current
from dataclasses import dataclass
import json
import re
import uuid

STATES = {"ready", "starting", "stopped", "unknown", "controller_stopped"}


class Fault(Exception):
    """Only fixed codes cross service boundaries; never forward exception text."""
    def __init__(self, code):
        if not re.fullmatch(r"[a-z_]{1,48}", code):
            raise ValueError("invalid_error_code")
        self.code = code
        super().__init__(code)


START_BLOCK_CODES = frozenset({'guard_busy', 'guard_maintenance', 'guard_unknown', 'mutations_disabled'})


class StartBlocked(Fault):
    """Durably refused before AMP dispatch; never infer this from a code alone."""
    def __init__(self, identity, user, code):
        if not job_id(identity) or not snowflake(user) or not isinstance(code, str) or code not in START_BLOCK_CODES:
            raise ValueError('invalid_blocked_receipt')
        super().__init__(code)
        self.identity, self.user = identity, user

    def public(self):
        return {'id': self.identity, 'user': self.user, 'code': self.code,
                'state': 'blocked', 'effect_attempted': False}

    @classmethod
    def parse(cls, value, identity, user):
        if (not isinstance(value, dict)
                or set(value) != {'id', 'user', 'code', 'state', 'effect_attempted'}
                or value['id'] != identity or value['user'] != user
                or value['state'] != 'blocked' or value['effect_attempted'] is not False
                or not isinstance(value['code'], str) or value['code'] not in START_BLOCK_CODES):
            raise Fault('broker_rejected')
        return cls(identity, user, value['code'])


def snowflake(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{16,19}", value) is not None


def job_id(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def decode(raw, limit=4096):
    if not isinstance(raw, bytes) or len(raw) > limit:
        raise Fault("invalid_message")
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("duplicate_key")
            result[k] = v
        return result
    try:
        result = json.loads(raw, object_pairs_hook=pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise Fault("invalid_message") from None


@dataclass(frozen=True)
class Request:
    interaction: str
    user: str
    guild: str
    channel: str
    application: str
    roles: tuple[str, ...]
    action: str
    target: str

    @classmethod
    def parse(cls, obj):
        fields = {"interaction", "user", "guild", "channel", "application", "roles", "action", "target"}
        if not isinstance(obj, dict) or set(obj) != fields:
            raise Fault("invalid_request")
        if not all(snowflake(obj[k]) for k in fields - {"roles", "action", "target"}):
            raise Fault("invalid_request")
        if (not isinstance(obj["roles"], list) or len(obj["roles"]) > 250
                or not all(snowflake(r) for r in obj["roles"])):
            raise Fault("invalid_request")
        if not isinstance(obj["action"], str) or not isinstance(obj["target"], str):
            raise Fault("invalid_request")
        return cls(**{**obj, "roles": tuple(obj["roles"])})

    def authorize(self):
        if ((self.guild, self.channel, self.application) != ((current().guild), (current().channel), (current().application))
                or not (self.user == (current().owner) or (current().role) in self.roles)):
            raise Fault("not_authorized")
        if (self.action, self.target) not in (current().commands):
            raise Fault("unsupported_command")

    @property
    def id(self):
        return str(uuid.uuid5(uuid.UUID((current().application).zfill(32)), self.interaction))
