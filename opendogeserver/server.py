""" Made by Shadofer#7312. """

""" BUILT-IN MODULES """
import asyncio

""" For hosting. """
from os import environ

""" Formatting responses. """
from json import dumps, loads
from json.decoder import JSONDecodeError

""" Getting hosting info. """
from socket import gethostname, gethostbyname

""" Specifying variable types. """
from typing import Dict, List, Set

""" Generating account IDs. """
from random import choice
from string import digits, ascii_letters, ascii_uppercase

""" Dataclasses. """
from dataclasses import dataclass, field

""" Remove the need for variables to specify events. """
from inspect import getmembers, ismethod

""" To prevent a simple exception at startup. """
from socket import gaierror

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets import serve
from websockets.client import WebSocketClientProtocol
from websockets.exceptions import ConnectionClosed

""" Email validation. """
from email_validator import validate_email, EmailNotValidError

""" Password hashing. """
from bcrypt import checkpw, gensalt, hashpw

""" LOCAL MODULES """

""" Not used yet, will attempt when Towers are implemented. Travellers coming soon. """
from opendogeserver.classes import *


""" ----- START OF SERVER ----- """


@dataclass(frozen=False, eq=False)
class Server:
    """ The base Server class. """

    """ PRIVATE VARIABLES """

    """ The main asyncio loop, for synchronous events. Use when performance is an issue/background tasks need to be created. """ 
    __loop = asyncio.get_event_loop()

    """ Telemetry. """
    __total_requests: int = 0

    """ To check the current registered emails. """
    __registered_emails: Set[str] = field(default_factory=set)

    """ For ratelimiting IPs. """
    __ip_requests: Dict[str, int] = field(default_factory=dict)

    """ PUBLIC VARIABLES """

    """ The registered accounts. """
    travellers: Dict[str, Traveller] = field(default_factory=dict)

    """ The registered towers/rooms. """
    towers: Dict[str, Tower] = field(default_factory=dict)

    """ Those which shouldn't be global, Server classes exist. """

    """ Max requests until IP ratelimits are cleared. """
    IP_RATELIMIT_MAX = 10

    """ Seconds between resetting IP ratelimits. """
    IP_RATELIMIT_CLEANUP_INTERVAL = 5

    """ Seconds between resetting IP requests. """
    IP_REQUESTS_CLEANUP_INTERVAL = 60 * 60

    """ Seconds between resetting IP account links. """
    IP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24

    """ Account-related. """
    MIN_ACCOUNT_NAME = 3
    MAX_ACCOUNT_NAME = 20
    MIN_PASS_LENGTH = 8
    MAX_PASS_LENGTH = 20
    MAX_ACCOUNTS_PER_IP = 5

    """ Links IPs to an account. """
    wss_accounts: Dict[str, str] = field(default_factory=dict)

    """ Server utility functions """

    def __transform_to_call(self, target: str, is_argument: bool = False) -> str:
        """Transforms a non python string to to a function/argument name.

        Args:
            target (str): The response's string.
            is_argument (bool): Whether or not it's going to be passed as an argument. Defaults to False.

        Returns:
            str: The formatted string.
        """
        target_list = list(target)

        for index, letter in enumerate(target_list):
            if letter in ascii_uppercase:
                target_list[index] = letter.lower()
                target_list.insert(index, '_')

        result = ''.join([letter for letter in target_list])

        return f"_Server__event_{result}" if not is_argument else result

    def __transform_to_original(self, target: str) -> str:
        """Transforms a previously-modified-by-transform_to_call argument to its original state.

        Args:
            target (str): The argument to restore.

        Returns:
            str: The restored agument.
        """
        target_list = list(target)

        for index, letter in enumerate(target_list):
            if letter == '_':
                target_list.pop(index)
                target_list[index] = target_list[index].upper()

        return ''.join([letter for letter in target_list])

    def __format_res(self, event_name: str, event_reply: str = 'Reply',**kwargs) -> dict:
        """Formats a response to be sent in an appropriate form, with optional keyword arguments.

        Args:
            event_name (str): The name of the event.
            event_reply (str): The string to concatenate to the event_name which will be the reply. Defaults to Reply.

        Returns:
            dict: The formatted response.
        """
        return dumps(dict(data=kwargs, event=f'{event_name}{event_reply}', originalEvent=event_name))

    def __format_res_err(self, event_name: str, event_reply: str, error_message: str, is_no_event_response: bool = False, **kwargs) -> dict:
        """Same as above but for errors.

        Args:
            event_name (str): The name of the event. Set to '' so as not to pass originalEvent to the response.
            event_reply (str): The string to concatenate to the event_name which will be the reply.
            error_message (str): The message of the error.
            is_no_event_response (bool): If True, event_reply wont be concatenated to event_name. This is helpful for general errors.

        Returns:
            dict: The formatted error response.
        """
        return dumps(dict(data={'errorMessage': error_message, **kwargs}, event=f'{event_name}{event_reply}' if not is_no_event_response else f'{event_reply}', originalEvent=event_name))

    def __check(self, data: dict, *args) -> None:
        """Checks pairs of a dictionary where the second key must denote the required type of the first one. eg: 
        
        ```self.__check({some_expected_int_var: int})```

        Args:
            data (dict): The dictionary to check.
        """
        for item, type in data:
            assert isinstance(item, type)

    def __check_loop_data(self, data: dict, keys: List[str]):        
        """Checks if a number of keys are present in a dictionary.

        Args:
            data (dict): The dictionary to check against.
            keys (List[str]): The keys which must be present the dictionary.

        Returns:
            None/str: None if the keys are present else an error string.
        """
        for key in keys:

            if key not in data:
                return f'Data must contain: {self.__transform_to_original(key)}'

            elif len(data[key].strip()) == 0:
                return f'{self.__transform_to_original(key)} value mustn\'t be empty.'

        return None

    def __gen_id(self) -> str:
        """Generates an ID with 15 digits for use when creating an account.

        Returns:
            str: The resulting ID.
        """
        result_id = ''

        for i in range(15):
            result_id += str(choice(f"{ascii_letters}{digits}"))

        return result_id

    def __check_account(self, request_ip: str) -> bool:
        """Checks whether or not an IP is associated with an account.

        Args:
            request_ip (str): The IP of the request.

        Returns:
            bool: Whether or not it is linked to an account.
        """
        if request_ip in self.wss_accounts:
            return True
        return False

    """ Server event functions """

    def __event_create_traveller(self, event: str, traveller_name: str, traveller_email: str, traveller_password: str, wss: WebSocketClientProtocol):
        """Creates a new traveller account.

        Args:
            traveller_name (str): The name of the traveller.
            traveller_email (str): The email of the traveller.
            traveller_password (str): The password of the traveller.
            wss (WebSocketClientProtocol): The websocket client.

        Possible Responses:
            createTravellerReply: The websocket has successfully created a traveller. No additional hashes have to be passed for future account-related methods.

            createTravellerEmailInvalid: The provided email is not formatted correctly.
            createTravellerEmailInUse: The provided email is already in use.
            createTravellerNameExceedsLimit: The provided name exceeds the current name length limitations.
            createTravellerPasswordExceedsLimit: The provided password exceeds the current password length limitations.
            createTravellerAlreadyLoggedIn: The IP is already logged in to another account.
            createTravellerMaxAccouns: The IP has created the maximum amount of accounts available.
        """

        if self.__check_account(wss.remote_address[0]):
            return self.__format_res_err(event, 'AlreadyLoggedIn', 'You are currently logged in. Logout and try again.')

        """ Don't exceed the limit per IP, before any other checks. """
        accounts_from_this_ip = 0

        for key, item in self.travellers.items():
            if item.traveller_creator_ip == wss.remote_address[0]:
                accounts_from_this_ip += 1

        if accounts_from_this_ip == self.MAX_ACCOUNTS_PER_IP:
            return self.__format_res_err(event, 'MaxAccounts', 'You have created the maximum amount of accounts available.')

        """ Remember to keep the strip methods, we need the original name. """
        if not len(traveller_name.strip()) >= self.MIN_ACCOUNT_NAME or not len(traveller_name.strip()) <= self.MAX_ACCOUNT_NAME:
            return self.__format_res_err(event, 'NameExceedsLimit', f'Traveller name must be between {self.MIN_ACCOUNT_NAME} and {self.MAX_ACCOUNT_NAME} characters long.')

        """ Validate the email, check if it has @ and a valid domain. """
        try:
            validate_email(traveller_email)
        except EmailNotValidError as e:
            return self.__format_res_err(event, 'EmailInvalid', str(e))

        """ Prevent duplicate emails. """
        if traveller_email in self.__registered_emails:
            return self.__format_res_err(event, 'EmailInUse', "This email is already in use.")

        if not len(traveller_password.strip()) >= self.MIN_PASS_LENGTH or not len(traveller_password.strip()) <= self.MAX_PASS_LENGTH:
            return self.__format_res_err(event, 'PasswordExceedsLimit', f'Traveller password must be between {self.MIN_PASS_LENGTH} and {self.MAX_PASS_LENGTH} characters.')

        """ Visible by fetchTravellers and its not at all private. """
        traveller_id = self.__gen_id()

        """ rounds=13 so as to exceed the 214ms bare limit according to: https://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256. """
        hashed_password = hashpw(bytes(traveller_password, encoding='ascii'), gensalt(rounds=13))

        self.travellers[traveller_id] = Traveller(traveller_id, wss.remote_address[0], traveller_name, traveller_email, hashed_password)

        """ Update registered emails and accounts links. """
        self.__registered_emails.add(traveller_email)
        self.wss_accounts[wss.remote_address[0]] = traveller_id

        return self.__format_res(event, travellerId=traveller_id)

    def __event_login_traveller(self, event: str, traveller_email: str, traveller_password: str, wss: WebSocketClientProtocol):
        """Logs in a websocket connection to a traveller account.

        Args:
            traveller_email (str): The traveller account's email to login to.
            traveller_password (str): The traveller account's password to check against.
            wss (WebSocketClientProtocol): The websocket client.

        Possible Responses:
            loginTravellerReply: The websocket has successfully connected to a traveller. No additional keys have to be passed for future account-related methods.

            loginTravellerNotFound: The traveller with the required ID could not be found.
            loginTravellerInvalidPassword: The given password doesn't match the original one.
            loginTravellerAlreadyLoggedIn: The requestee is already logged into an account.
            loginTravellerAccountTaken: The target account is already taken by another IP.
            loginTravellerPasswordExceedsLimit: The provided password exceeds current password length limitations.
        """

        """ Determine which id the email is associated with. """
        if not traveller_email in self.__registered_emails:
            return self.__format_res_err(event, 'NotFound', 'The specified traveller could not be found.')

        for key, item in self.travellers.items():
            if item.traveller_email == traveller_email:
                traveller_id = item.traveller_id

        """ Check if the requestee is already logged into an account. """
        if self.__check_account(wss.remote_address[0]):
            return self.__format_res_err(event, 'AlreadyLoggedIn', 'You are currently logged in. Logout and try again.')

        """ Check password validity. """
        if not len(traveller_password.strip()) >= self.MIN_PASS_LENGTH or not len(traveller_password.strip()) <= self.MAX_PASS_LENGTH:
            return self.__format_res_err(event, 'PasswordExceedsLimit', f'Traveller password must be between {self.MIN_PASS_LENGTH} and {self.MAX_PASS_LENGTH} characters.')

        """ Check if someone has already logged into this account. """
        for key, item in self.wss_accounts.items():
            if item == traveller_id:
                return self.__format_res_err(event, 'AccountTaken', 'Another user has already logged into this account.')

        if checkpw(bytes(traveller_password, encoding='ascii'), self.travellers[traveller_id].traveller_password):

            """ Link the IP to an account. """
            self.wss_accounts[wss.remote_address[0]] = traveller_id

            return self.__format_res(event, travellerId=traveller_id)

        return self.__format_res_err(event, 'InvalidPassword', f'The password is invalid.')

    def __event_logout_traveller(self, event: str, wss: WebSocketClientProtocol):
        """Logs out a user from his associated traveller, if any. 
        
        Args:
            wss (WebSocketClientProtocol): The websocket client.

        Possible Responses:
            logoutTravellerReply: The IP has successfully logged out of the associated account.

            logoutTravellerNoAccount: There is no account associated with this IP address.
        """
        if wss.remote_address[0] in self.wss_accounts:
            del self.wss_accounts[wss.remote_address[0]]

            return self.__format_res(event)
        return self.__format_res_err(event, 'NoAccount', 'There is no account associated with this IP.')

    def __event_fetch_traveller(self, event: str, traveller_id: str):
        """Fetches a traveller's info, if he exists in the database.

        Args:
            traveller_id (str): The id of the traveller to fetch info from.

        Possible Responses:
            fetchTravellerReply: Info about a traveller has been successfully fetched.

            fetchTravellerNotFound: The traveller with the required ID could not be found.
        """
        if traveller_id in self.travellers:
            return self.__format_res(event, travellerName=self.travellers[traveller_id].traveller_name, travellerId=traveller_id)
        return self.__format_res_err(event, 'NotFound', f'Traveller with id {traveller_id} not found.')

    def __event_fetch_travellers(self, event: str):
        """Fetches every single present traveller's info.
        
        Possible Responses:
            fetchTravellersReply: The existing traveller IDs have been successfully fetched.
        """
        return self.__format_res(event, travellerIds=[id for id in self.travellers])

    def __event_total_travellers(self, event: str):
        """Returns the number of the total travellers present.
        
        Possible Responses:
            totalTravellersReply: The number of existing travellers has been successfully fetched.
        """
        return self.__format_res(event, totalTravellers=len(self.travellers))

    """ Entry functions """

    async def __request_switcher(self, wss: WebSocketClientProtocol, data: dict):
        """Switches events according to the data provided.

        Args:
            wss (WebSocketClientProtocol): The client waiting for a response.
            data (dict): The data sent by the client.

        Returns:
            dict: The response according to the request. Nothing may be returned, which means the request is invalid and that __current_error should be output.

        Possible Responses:
            EventNotFound: The given event could not be found.
            EvenNotImplemented: The given event is currently under maintenance.
            EventUnknownError: There was an error processing the event.
        """

        """ Refuse to process dictionaries without an event key, which must be atleast 1 character long. """
        try:
            event = data['event']
            assert len(data['event']) > 0
        except:
            return

        try:
            """ Check if arguments are given. """
            target_function: function = dict(getmembers(self, ismethod))[self.__transform_to_call(event)]
            
            target_arg_names = list(target_function.__code__.co_varnames)
            target_arg_names.remove('self')

            """ Sometimes contains function variables. """
            target_arg_names = [arg for arg in target_arg_names if target_arg_names.index(arg) < len(target_arg_names)]

            """ Keyword arguments to pass to the function. """
            target_args = {}

            for arg, value in data.items():
                if self.__transform_to_call(arg, True) in target_arg_names:
                    arg_to_add = self.__transform_to_call(arg, True)
                    
                    """ Preserve event name. """
                    if arg == 'event':
                        arg_to_add = arg

                    target_args[arg_to_add] = value

            """ Custom arguments to pass manually. """
            if 'wss' in target_arg_names:
                target_args['wss'] = wss

            try:
                return target_function(**target_args)
            except:
                """ It is the only error possible at this time. """
                return self.__format_res_err(event, 'FormatError', self.__check_loop_data(target_args, target_arg_names))

        except KeyError:
            """ Provide the user with the available events, in a seperate key to be able to split them. """
            possible_events = [self.__transform_to_original(event.replace('_Server__event_', '')) for event in dict(getmembers(self, ismethod)) if event.startswith('_Server__event')]

            events_response = ''

            for index, ev in enumerate(possible_events):
                events_response = f"{events_response}{ev}|" if index + 1 < len(possible_events) else f"{events_response}{ev}"

            return self.__format_res_err(event, 'EventNotFound', 'This event doesn\'t exist.', True, possibleEvents=events_response)

    async def serve(self, wss: WebSocketClientProtocol, path: str) -> None:
        """Called only by websockets.serve, provides start_server with info.

        Args:
            wss (WebSocketClientProtocol): The websocket client.
            path (str): The path which the client wants to access.
        """
        print('A traveller has connected.')

        """ Set to 0 ONLY if the ip doesn't exist since previous IPs are stored even if it disconnects. """
        if wss.remote_address[0] not in self.__ip_requests:
            self.__ip_requests[wss.remote_address[0]] = 0

        while True:
            try:
                response = await wss.recv()

                """ Prevent malicious intents. """
                if self.__ip_requests[wss.remote_address[0]] > self.IP_RATELIMIT_MAX:
                    continue

                self.__ip_requests[wss.remote_address[0]] += 1

                data = loads(response)

                assert isinstance(data, dict)

                """ Prevent strange values. """
                for key, item in data.items():
                    assert isinstance(key, str)
                    assert isinstance(item, str)

                result = await self.__request_switcher(wss, data)

                """ If nothing is returned, skip this call. """
                if not result:
                    continue

                await wss.send(result)

                self.__total_requests += 1

                print(f'[{self.__total_requests}] Reply sent for \'{data["event"]}\'.')

            except JSONDecodeError or AssertionError:
                continue

            except ConnectionClosed as e:
                print(f'A traveller has disconnected with code {e.code}.')

                """ Don't remove from IP ratelimit list. """

                break

    """ Tasks """
    async def __task_cleanup_ip_ratelimits(self) -> None:
        """Resets the IP ratelimits for every traveller. """
        while True:
            for ip in self.__ip_requests:
                self.__ip_requests[ip] = 0

            await asyncio.sleep(self.IP_RATELIMIT_CLEANUP_INTERVAL)

    async def __task_cleanup_ip_requests(self) -> None:
        """Resets the IP requests dictionary to delete cached IPs. """
        while True:
            self.__ip_requests.clear()
            await asyncio.sleep(self.IP_REQUESTS_CLEANUP_INTERVAL)

    async def __task_cleanup_account_links(self) -> None:
        """Resets the accounts linked to each IP. """
        while True:
            self.wss_accounts.clear()
            await asyncio.sleep(self.IP_ACCOUNT_CLEANUP_INTERVAL)

""" ----- END OF SERVER ----- """


if __name__ == '__main__':
    """ Heroku expects us to bind on a specific port, if deployed locally we can bind anywhere. """
    port = environ.get('PORT', 5000)

    server = Server()

    start_server = serve(server.serve, '0.0.0.0', port)

    try:
        print(f'Server running at: {gethostbyname(gethostname())}:{port}')
    except gaierror:
        print(f'Server running at port: {port}')

    loop = asyncio.get_event_loop()

    loop.run_until_complete(start_server)

    """ Dynamically find and start server tasks. """
    registered_tasks = [task for task_name, task in dict(getmembers(server, ismethod)).items() if task_name.startswith('_Server__task')]

    for task in registered_tasks:
        loop.create_task(task())

    if len(registered_tasks) > 0:
        print('Tasks started.')

    """ Start the infinite server loop. """
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(f'Server shut down due to an error: \n{e.__traceback__}')
