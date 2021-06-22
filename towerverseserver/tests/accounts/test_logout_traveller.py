""" logoutTraveller test. """

""" BUILT-IN MODULES """
from json import dumps, loads

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets.client import connect

""" Ordering and running asynchronous tests. """
import pytest

@pytest.mark.asyncio
@pytest.mark.run(order=7)
async def test_logout_traveller_response():
    async with connect('ws://localhost:5000') as wss:

        await wss.send(dumps({'event': 'logoutTraveller'}))

        response = loads(await wss.recv())

        assert isinstance(response, dict) and response['event'] == 'logoutTravellerReply'
