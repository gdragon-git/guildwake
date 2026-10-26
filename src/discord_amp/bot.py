"""Discord Gateway frontend. Dependency imported only by the bot entry point."""
from .config import current
import asyncio
import logging
from dataclasses import asdict

from .model import Request, Fault
from .wire import rpc

MESSAGES = {
    'ready': 'Enshrouded is ready (AMP and LAN query checked for start jobs).',
    'starting': 'Enshrouded is starting.', 'stopped': 'AMP reports Enshrouded stopped.',
    'controller_stopped': 'The Enshrouded controller is stopped.',
    'amp_available': 'Authenticated AMP is available.',
    'guard_busy': 'Another game instance has activity. Start refused.',
    'guard_maintenance': 'AMP maintenance tasks are active. Start refused.',
    'guard_unknown': 'The local guard could not verify a safe start. Start refused.',
    'unknown': 'Outcome unknown. An owner review is required before another action.',
    'deadline': 'The readiness deadline expired. No action will be replayed.',
    'broker_unavailable': 'The host broker is unreachable; this does not prove the host is asleep.',
    'mutations_disabled': 'Wake and start are disabled pending deployment qualification.',
    'cooldown': 'Please wait for the command cooldown.',
    'review_required': 'An unfinished or uncertain action needs owner review.',
    'host_busy': 'A wake-only job is active. Wait for it to finish before requesting start.',
    'already_running': 'Enshrouded is already running or starting; no new start was sent.',
    'not_authorized': 'This command is unavailable for your account or this channel.',
    'audit_unavailable': 'Durable records are unavailable. New actions are refused.',
}


def build_client(token, socket_path, controller_uid):
    import discord
    from discord import app_commands

    class Client(discord.Client):
        def __init__(self):
            # Member.roles resolves the interaction's role IDs through the guild
            # role cache. GUILDS supplies that metadata; privileged intents stay off.
            super().__init__(intents=discord.Intents(guilds=True), application_id=int((current().application)))
            self.tree = app_commands.CommandTree(self)

        async def setup_hook(self):
            app = await self.application_info()
            if str(app.id) != (current().application):
                raise Fault('not_authorized')
            # Guild-only sync does not change the existing integration's
            # configured role/channel permission overwrites.
            await self.tree.sync(guild=discord.Object(id=int((current().guild))))

    client = Client()

    async def dispatch(interaction, action, target):
        roles = tuple(str(role.id) for role in interaction.user.roles) if isinstance(interaction.user, discord.Member) else ()
        req = Request(str(interaction.id), str(interaction.user.id), str(interaction.guild_id),
                      str(interaction.channel_id), str(interaction.application_id), roles, action, target)
        # Fast local rejection; controller reauthorizes independently.
        try:
            req.authorize()
        except Fault:
            await interaction.response.send_message(MESSAGES['not_authorized'], ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True, thinking=True)
        message = {'operation': 'submit', 'request': {**asdict(req), 'roles': list(req.roles)}}
        try:
            result = await rpc(socket_path, message, controller_uid)
            job = result['job']
            if action != 'status':
                for _ in range(168):  # <=14 minutes, inside Discord's 15-minute token lifetime
                    await interaction.edit_original_response(content=f"Job {job}: {MESSAGES.get(result['code'], 'Request in progress.')}")
                    await asyncio.sleep(5)
                    result = await rpc(socket_path, {'operation': 'progress', 'request': message['request'], 'job': job}, controller_uid)
                    if result['terminal']:
                        break
            # A status-only ready result has not done the combined A2S check.
            if action == 'status':
                if result.get('status', {}).get('amp_available') is True:
                    text = f"Host: reachable through the broker. Authenticated AMP: available. Enshrouded: {result['code']}. A player join is not verified."
                else:
                    text = 'Host: unverified. Authenticated AMP: unverified. Enshrouded: unknown. This check does not wake the host.'
            else:
                text = MESSAGES.get(result['code'], 'Request finished. Check the job record.')
            await interaction.edit_original_response(content=f'Job {job}: {text}')
        except Exception as exc:
            code = exc.code if isinstance(exc, Fault) else 'unknown'
            await interaction.edit_original_response(content=MESSAGES.get(code, 'Request failed. No action will be replayed.'))

    server = app_commands.Group(name='server', description='Game host availability', guild_only=True)
    game = app_commands.Group(name='game', description='Approved game actions', guild_only=True)

    @server.command(name='status', description='Read host and Enshrouded status without waking it')
    @app_commands.choices(host=[app_commands.Choice(name=current().host, value=current().host)])
    async def status(interaction: discord.Interaction, host: str):
        await dispatch(interaction, 'status', host)

    @server.command(name='wake', description='Wake the configured host and wait for authenticated AMP')
    @app_commands.choices(host=[app_commands.Choice(name=current().host, value=current().host)])
    async def wake(interaction: discord.Interaction, host: str):
        await dispatch(interaction, 'wake', host)

    @game.command(name='start', description='Wake if needed, then request Enshrouded startup')
    @app_commands.choices(game=[app_commands.Choice(name=current().game, value=current().game)])
    async def start(interaction: discord.Interaction, game: str):
        await dispatch(interaction, 'start', game)

    guild = discord.Object(id=int((current().guild)))
    client.tree.add_command(server, guild=guild)
    client.tree.add_command(game, guild=guild)
    return client


def run(token, path, uid):
    # Do not install discord.py's default file/stream logger; HTTP exceptions
    # and interaction objects are never written to durable application logs.
    logger = logging.getLogger('discord')
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    client = build_client(token, path, uid)
    client.run(token, log_handler=None)
