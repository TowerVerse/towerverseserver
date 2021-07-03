"""
License: GPL-3

Maintainer: Shadofer#0001

Contributors: 

File description:
    The test regarding the fetchTraveller response.

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
@pytest.mark.run(order=7)
async def test_fetch_traveller_response():
    async with connect('ws://localhost:5000') as wss:

        await wss.send(dumps({'event': 'fetchTravellers'}))

        user_ids = loads(await wss.recv())['data']['travellerIds']

        for id in user_ids:
            await wss.send(dumps({'event': 'fetchTraveller', 'travellerId': id}))

            response = loads(await wss.recv())

            assert isinstance(response, dict) and response['event'] == 'fetchTravellerReply'

