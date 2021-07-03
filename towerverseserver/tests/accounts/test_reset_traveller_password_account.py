"""
License: GPL-3

Maintainer: Shadofer#0001

Contributors: 

File description:
    The test regarding the resetTravellerPasswordAccount response.

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
@pytest.mark.run(order=11)
async def test_reset_traveller_password_response():
    async with connect('ws://localhost:5000') as wss:

        await wss.send(dumps({'event': 'resetTravellerPasswordAccount', 'oldTravellerPassword': 'testpassword123',
                            'newTravellerPassword': 'testpassword123'}))

        response = loads(await wss.recv())

        assert isinstance(response, dict) and response['event'] == 'resetTravellerPasswordAccountReply'
