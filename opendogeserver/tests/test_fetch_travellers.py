""" fetchTravellers test. """

import websockets
from json import dumps, loads
import pytest

@pytest.mark.asyncio
@pytest.mark.run(order=2)
async def test_fetch_travellers_response():
    async with websockets.connect('ws://localhost:5000') as wss:

        await wss.send(dumps({'event': 'fetchTravellers'}))

        response = loads(await wss.recv())

        assert isinstance(response, dict) and response['event'] == 'fetchTravellersReply'
