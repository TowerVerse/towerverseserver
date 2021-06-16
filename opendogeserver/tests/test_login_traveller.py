""" loginTraveller test. """

import websockets
from json import dumps, loads
import pytest

@pytest.mark.asyncio
@pytest.mark.run(order=7)
async def test_create_traveller_response():
    async with websockets.connect('ws://localhost:5000') as wss:

        await wss.send(dumps({'event': 'loginTraveller', 'travellerEmail': 'testemail@gmail.com',
                            'travellerPassword': 'testpassword123'}))

        response = loads(await wss.recv())

        assert isinstance(response, dict) and response['event'] == 'loginTravellerReply'
