import profile_fixture
"""Real library role objects and HTTP-200 auth failures; no real login/API actions."""
import io,json,unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock,patch
from discord_amp.amp import Session
from discord_amp.model import Fault
from profile_fixture import ROLE, GUILD, CHANNEL, APPLICATION

class Reply:
    headers={}
    def __init__(self,value):self.value=value
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def read(self,*args):return json.dumps(self.value).encode()

class Opener:
    def __init__(self,values):self.values=list(values);self.calls=[]
    def open(self,request,**kwargs):
        self.calls.append(request.full_url.rsplit('/',1)[-1])
        return Reply(self.values.pop(0))

class SessionRefreshTests(unittest.TestCase):
    def test_http_200_unauthorized_read_refreshes_once(self):
        session=Session('','unused-fixture-password');session.token='old-fixture-token'
        session.opener=Opener([{'Title':'Unauthorized Access'}, {'success':True,'sessionID':'new-fixture-token'}, []])
        self.assertEqual(session.read('ADSModule','GetInstanceStatuses'),[])
        self.assertEqual(session.opener.calls,['GetInstanceStatuses','Login','GetInstanceStatuses'])
        self.assertEqual(session.token,'new-fixture-token')
    def test_second_unauthorized_read_stops_without_another_refresh(self):
        session=Session('','unused-fixture-password');session.token='old-fixture-token'
        session.opener=Opener([{'Title':'Unauthorized Access'}, {'success':True,'sessionID':'new-fixture-token'}, {'Title':'Unauthorized Access'}])
        with self.assertRaises(Fault) as caught:session.read('ADSModule','GetInstanceStatuses')
        self.assertEqual(caught.exception.code,'amp_authentication_failed')
        self.assertEqual(session.opener.calls,['GetInstanceStatuses','Login','GetInstanceStatuses'])
    def test_http_200_unauthorized_start_never_retries(self):
        CHILD = profile_fixture.PROFILE.child_route
        session=Session(CHILD,'unused-fixture-password');session.token='old-fixture-token'
        session.opener=Opener([{'Title':'Unauthorized Access'}])
        with self.assertRaises(Fault) as caught:session.call('Core','Start',{},authorize=lambda:None)
        self.assertEqual(caught.exception.code,'amp_authentication_failed')
        self.assertEqual(session.opener.calls,['Start'])
    def test_generic_error_stays_unknown_without_login(self):
        session=Session('','unused-fixture-password');session.token='old-fixture-token'
        session.opener=Opener([{'Error':'fixture-generic-error'}])
        with self.assertRaises(Fault) as caught:session.read('ADSModule','GetInstanceStatuses')
        self.assertEqual(caught.exception.code,'amp_unknown')
        self.assertEqual(session.opener.calls,['GetInstanceStatuses'])

try:import discord
except ImportError:discord=None

@unittest.skipUnless(discord,'Pinned discord.py required for real Member/cache tests')
class RealMemberCacheTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from discord_amp.bot import build_client
        self.client=build_client('unused-fixture-token','never-connect',1)
    async def asyncTearDown(self):await self.client.close()
    def guild(self,hydrated):
        roles=[] if not hydrated else [{'id':value,'name':name,'permissions':'0','position':position,'color':0,'hoist':False,'managed':False,'mentionable':False,'flags':0}
            for value,name,position in [(GUILD,'@everyone',0),(ROLE,'Game Server Members',1)]]
        return discord.Guild(state=self.client._connection,data={'id':GUILD,'name':'fixture','unavailable':True,'roles':roles})
    def interaction(self,hydrated,roles=(ROLE,)):
        member=discord.Member(state=self.client._connection,guild=self.guild(hydrated),data={'user':{'id':'100000000000000099','username':'fixture','discriminator':'0','avatar':None},'roles':list(roles),'flags':0})
        return SimpleNamespace(id=1561700000000000000,user=member,guild_id=int(GUILD),channel_id=int(CHANNEL),application_id=int(APPLICATION),
            response=SimpleNamespace(defer=AsyncMock(),send_message=AsyncMock()),edit_original_response=AsyncMock())
    def command(self):return self.client.tree.get_command('server',guild=discord.Object(id=int(GUILD))).get_command('status')
    async def test_only_guilds_intent_enabled(self):
        self.assertTrue(self.client.intents.guilds)
        self.assertEqual(self.client.intents.value,1)
        self.assertFalse(self.client.intents.members);self.assertFalse(self.client.intents.message_content);self.assertFalse(self.client.intents.presences)
    async def test_real_member_with_cached_role_authorized_privately(self):
        interaction=self.interaction(True)
        with patch('discord_amp.bot.rpc',AsyncMock(return_value={'job':'00000000-0000-4000-8000-000000000001','code':'ready','status':{'amp_available':True}})) as rpc:
            await self.command().callback(interaction,'gameserver')
        self.assertEqual(rpc.await_count,1)
        self.assertIn(ROLE,rpc.call_args.args[1]['request']['roles'])
        interaction.response.defer.assert_awaited_once_with(ephemeral=True,thinking=True)
    async def test_real_member_missing_cache_remains_denied_without_rpc(self):
        interaction=self.interaction(False)
        with patch('discord_amp.bot.rpc',AsyncMock()) as rpc:await self.command().callback(interaction,'gameserver')
        rpc.assert_not_awaited();self.assertTrue(interaction.response.send_message.call_args.kwargs['ephemeral'])
    async def test_real_member_without_required_role_denied_without_rpc(self):
        interaction=self.interaction(True,())
        with patch('discord_amp.bot.rpc',AsyncMock()) as rpc:await self.command().callback(interaction,'gameserver')
        rpc.assert_not_awaited();self.assertTrue(interaction.response.send_message.call_args.kwargs['ephemeral'])
