"""
License: GPL-3

Maintainer: Shadofer#0001

Contributors: 

File description:
    The test regarding the fetchGuilds response.

Extra info:
    None
"""

""" BUILT-IN MODULES """
from json import dumps, loads

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets.client import connect

""" Ordering and running asynchronous tests. """
import pytest


@pytest.mark.asyncio
@pytest.mark.run(order=18)
async def test_fetch_guilds_response():
    async with connect('ws://localhost:5000') as wss:

        await wss.send(dumps({'event': 'fetchGuilds'}))

        response = loads(await wss.recv())

        assert isinstance(response, dict) and response['event'] == 'fetchGuildsReply' and response['data']['guildIds'][0] == '123456'
