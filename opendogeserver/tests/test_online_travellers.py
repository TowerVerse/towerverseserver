""" onlineTravellers test. """

import websockets
from json import dumps, loads
import pytest

@pytest.mark.asyncio
@pytest.mark.run(order=4)
async def test_online_travellers_response():
    async with websockets.connect('ws://localhost:5000') as wss:

        await wss.send(dumps({'event': 'onlineTravellers'}))

        response = loads(await wss.recv())

        assert isinstance(response, dict) and response['event'] == 'onlineTravellersReply' and response['data']['onlineTravellers'] == 1
