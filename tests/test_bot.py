import profile_fixture
"""Real discord.py command construction, with no login/sync/Gateway connection."""
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
try:
    import discord
except ImportError:
    discord = None
from profile_fixture import GUILD, OWNER, ROLE, CHANNEL, APPLICATION


@unittest.skipUnless(discord, 'Install pinned Discord extra for frontend contract checks')
class BotTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from discord_amp.bot import build_client
        self.client = build_client('unused-test-token', 'unused-test-socket', 123)
    async def asyncTearDown(self):
        await self.client.close()
    def interaction(self, user=OWNER, roles=(), guild=GUILD):
        member = MagicMock(spec=discord.Member)
        member.id = int(user)
        member.roles = [SimpleNamespace(id=int(role)) for role in roles]
        return SimpleNamespace(id=1561200000000000000, user=member, guild_id=int(guild),
            channel_id=int(CHANNEL), application_id=int(APPLICATION),
            response=SimpleNamespace(defer=AsyncMock(), send_message=AsyncMock()), edit_original_response=AsyncMock())
    def command(self):
        return self.client.tree.get_command('server', guild=discord.Object(id=int(GUILD))).get_command('status')
    async def test_exact_three_guild_commands_no_privileged_intents(self):
        groups=self.client.tree.get_commands(guild=discord.Object(id=int(GUILD)))
        self.assertEqual({(g.name,c.name) for g in groups for c in g.commands},
                         {('server','status'),('server','wake'),('game','start')})
        self.assertEqual(self.client.tree.get_commands(),[])
        self.assertFalse(self.client.intents.members)
        self.assertFalse(self.client.intents.message_content)
        self.assertFalse(self.client.intents.presences)
        self.assertEqual([x.value for x in self.command().parameters[0].choices],['gameserver'])
    async def test_role_context_is_forwarded_and_response_private(self):
        interaction=self.interaction('123456789123456789',(ROLE,))
        with patch('discord_amp.bot.rpc',AsyncMock(return_value={'job':str(uuid.uuid4()),'code':'ready','status':{'amp_available':True}})) as call:
            await self.command().callback(interaction,'gameserver')
            interaction.response.defer.assert_awaited_once_with(ephemeral=True,thinking=True)
            self.assertEqual(call.call_args.args[1]['request']['roles'],[ROLE])
            interaction.edit_original_response.assert_awaited_once()
            text=interaction.edit_original_response.call_args.kwargs['content']
            self.assertIn('Host: reachable',text)
            self.assertIn('Authenticated AMP: available',text)
    async def test_wrong_channel_denied_before_rpc(self):
        interaction=self.interaction(); interaction.channel_id=123456789123456789
        with patch('discord_amp.bot.rpc',AsyncMock()) as call:
            await self.command().callback(interaction,'gameserver')
            call.assert_not_awaited()
            self.assertTrue(interaction.response.send_message.call_args.kwargs['ephemeral'])
    async def test_unknown_membership_denied(self):
        interaction=self.interaction('123456789123456789')
        with patch('discord_amp.bot.rpc',AsyncMock()) as call:
            await self.command().callback(interaction,'gameserver')
            call.assert_not_awaited()


if __name__=='__main__': unittest.main()
