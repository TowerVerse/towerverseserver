"""

   Shadofer#0001 and Otterlord#3653
   Copyright GPL-3 
   
"""

""" BUILT-IN MODULES """

import asyncio

""" Parsing responses. """
from json import loads
from json.decoder import JSONDecodeError

""" Specifying variable types. """
from typing import ClassVar, Dict, Awaitable

""" Inspecting functions. """
from inspect import getfullargspec

""" Performance reports. """
from time import time

""" Generating unique IDs. """
from uuid import uuid4

""" Getting error tracebacks. """
from sys import exc_info

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets.exceptions import ConnectionClosed
from websockets.client import WebSocketClientProtocol

""" Production server MongoDB. """
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import OperationFailure

""" LOCAL MODULES """
from opendogeserver.utilities import *
from opendogeserver.constants import *
from opendogeserver.classes import *

class Server():
    """The `Server` class handles all requests/responses."""

    """ The Mongo Database. """
    mdb: Database = None
    
    """ The registered events to callback. """
    events: dict = {}
    
    """ The registered accounts. """
    travellers: Dict[str, Traveller] = {}
        
    """ Linking IPs to accounts. """
    wss_accounts: Dict[str, str] = {}

    """ Determine whether this is a self-hosted simulation, passed at initialisation. """
    IS_LOCAL: bool = None
    
    """ Passed reference to facilitate wrapper-fetching. """
    current_ref: str = None
            
    def __init__(self):
        """ Telemetry. """
        self.total_requests = 0
        self.ip_requests: Dict[str, int] = {}

    def register(self, callback: Awaitable) -> None:
        """Register an event"""
        event = to_camel_case(callback.__name__)
        if event not in self.events:
            self.events[event] = callback

    async def handle_request(self, wss: WebSocketClientProtocol, data: dict) -> str:
        """Switches events according to the data provided.
        
        Args:
            wss (WebSocketClientProtocol): The client waiting for a response.
            data (dict): The data sent by the client.
            
        Returns:
            dict: The response according to the request. Nothing may be returned, which means that the request should fail silently.
            
        Possible Responses:
            EventNotFound: The given event could not be found.
            EventUnknownError: There was an error processing the event.
            FormatError: The format of the error is incorrect.
        """

        """ Refuse to process dictionaries without an event key, which must be atleast 1 character long. """
        try:
            event = data['event']
            assert len(data['event']) > 0
        except AssertionError or KeyError:
            return

        try:
            target: function = self.events[to_snake_case(event)]

            target_args_names = getfullargspec(target).args
            target_args_names.remove('self')

            """ Keyword arguments to pass to the function. """
            target_args = {}

            for arg, value in data.items():
                arg_to_add = to_snake_case(arg, True)
                
                if arg_to_add in target_args_names:
                    """ Preserve event name. """
                    if arg == 'event':
                        arg_to_add = arg
                        
                    target_args[arg_to_add] = value

            """ Custom arguments to pass manually. """
            if 'wss' in target_args_names:
                target_args['wss'] = wss

            """ Check for arguments before calling, the call may not error but some arguments may be empty. """
            args_errored = check_loop_data(target_args, target_args_names)

            if args_errored:
                return format_res_err(event, 'FormatError', args_errored, True, ref=Server.current_ref)
            try:
                return target(**target_args)
            
            except Exception as e:
                """ Create bug report. """
                if self.IS_LOCAL:
                    print(exc_info())
                else:
                    self.mdb.logs.insert_one({f'bug-{str(uuid4())}': exc_info()})

                return format_res_err(event, 'EventUnknownError', 'Unknown internal server error.', True, ref=Server.current_ref)
            
        except KeyError:
            """ Provide the user with the available events, in a seperate key to be able to split them. """
            possible_events = [to_camel_case(event.replace('event_', '')) for event in self.events.keys()]

            events_response = ''

            for i, ev in enumerate(possible_events):
                events_response = f"{events_response}{ev}|" if i + 1 < len(possible_events) else f"{events_response}{ev}"
                
            return format_res_err(event, 'EventNotFound', 'This event doesn\'t exist.', True, ref=Server.current_ref, possibleEvents=events_response)

    async def serve(self, wss: WebSocketClientProtocol, path: str) -> None:
        """Called only by websockets.serve.

        Args:
            wss (WebSocketClientProtocol): The websocket client.
            path (str): The path which the client wants to access.
        """

        print(f'A traveller has connected. Travellers online: {len(Server.wss_accounts)}')

        """ Set to 0 ONLY if the ip doesn't exist since previous IPs are stored even if it disconnects. """
        if wss.remote_address[0] not in self.ip_requests:
            self.ip_requests[wss.remote_address[0]] = 0

        """ Infinite server loop. """
        while True:
            try:
                response = await wss.recv()

                """ Prevent malicious intents. """
                if self.ip_requests[wss.remote_address[0]] > IP_RATELIMIT_MAX:
                    continue

                self.ip_requests[wss.remote_address[0]] += 1

                try:
                    data = loads(response)
                except JSONDecodeError:
                    continue

                try:
                    assert isinstance(data, dict)
                    
                    """ Prevent strange values. """
                    for key, item in data.items():
                        assert isinstance(key, str)
                        assert isinstance(item, str)
                except AssertionError:
                    continue

                """ Remember to return passed reference. """
                if 'ref' in data:
                    Server.current_ref = data['ref']

                """ Convert to dict for checks. """
                result = await self.handle_request(wss, data)

                """ If nothing is returned, skip this call. """
                if not result:
                    continue

                await wss.send(result)

                self.total_requests += 1

                result = loads(result)

                print(f"[{self.total_requests}] {result['originalEvent']}: {result['event']}")

                """ Reset ref. """
                Server.current_ref = None

            except ConnectionClosed as e:
                """ Don't remove traveller from IP requests, prevent spam. """

                """ Remove a traveller from the linked accounts list, not online anymore. Only for production servers. """
                if wss.remote_address[0] in self.wss_accounts and not self.IS_LOCAL:
                    del self.wss_accounts[wss.remote_address[0]]

                print(f'A traveller has disconnected. Code: {e.code} | Travellers online: {len(self.wss_accounts)}')

                break

    def setup_mongo(self, mongodb_username: str, mongodb_password: str) -> None:
        """Sets up MongoDB for production servers.

        Args:
            mongodb_username (str): The username of an authored user of the database.
            mongodb_password (str): The password of the authored user.
        """
        start = time()

        try:
            mdbclient = MongoClient(f'mongodb+srv://{mongodb_username}:{mongodb_password}@{mongo_project_name}.vevnl.mongodb.net/{mongo_database_name}?{mongo_client_extra_args}')

            mdb = mdbclient[mongo_database_name]

            """ Prevent cold-booting MongoDB's first request in responses, use a random collection. """
            mdb.some_random_collection.count_documents({})

            print(f'Successfully setup MongoDB in {int(round(time() - start, 2) * 1000)} ms.')

            Server.mdb = mdb

        except OperationFailure:
            print('Invalid username or password provided for MongoDB, exiting.')
            exit()

    async def task_cleanup_ip_ratelimits(self) -> None:
        """Resets the IP ratelimits for every traveller. """

        while True:
            for ip in self.ip_requests:
                self.ip_requests[ip] = 0

            await asyncio.sleep(IP_RATELIMIT_CLEANUP_INTERVAL)

    async def task_cleanup_ip_requests(self) -> None:
        """Resets the IP requests dictionary to delete cached IPs. """

        while True:
            self.ip_requests.clear()
            await asyncio.sleep(IP_REQUESTS_CLEANUP_INTERVAL)

    async def task_cleanup_account_links(self) -> None:
        """Resets the accounts linked to each IP. """

        while True:
            self.wss_accounts.clear()
            await asyncio.sleep(IP_ACCOUNT_CLEANUP_INTERVAL)
