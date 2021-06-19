"""

Made by Shadofer#0001.
Pass --tests in order to disable database-related methods. Otherwise set environmental variables for MongoDB.

"""

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
from typing import Dict, List

""" Generating account IDs. """
from random import choice
from string import digits, ascii_letters, ascii_uppercase

""" Inspect functions. """
from inspect import getfullargspec

""" To prevent a simple exception at startup. """
from socket import gaierror

""" Performance reports. """
from time import time

""" Generating account hashes. """
from uuid import uuid4

""" Getting command-line arguments and tracebacks. """
from sys import argv, exc_info

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets import serve as ws_serve
from websockets.client import WebSocketClientProtocol
from websockets.legacy.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed

""" Email validation. """
from email_validator import validate_email, EmailNotValidError

""" Password hashing. """
from bcrypt import checkpw, gensalt, hashpw

""" MongoDB. """
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import OperationFailure

""" LOCAL MODULES """

from opendogeserver.classes import *


""" Global variables. """

""" The main asyncio loop, for synchronous events. Use when performance is an issue/background tasks need to be created. """ 
loop = asyncio.get_event_loop()

""" Telemetry. """
total_requests = 0

""" For ratelimiting IPs. """
ip_requests: Dict[str, int] = {}

""" ONLY USED FOR THE LOCAL VERSION """

""" The registered accounts. """
travellers: Dict[str, Traveller] = {}

""" The registered towers/rooms. """
towers: Dict[str, Tower] = {}

""" ONLY USED FOR THE LOCAL VERSION """

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

""" Accounts linked to IPs. """
wss_accounts: Dict[str, str] = {}

""" Whether or not this is a locally-hosted server. """
IS_LOCAL = '--local' in argv

""" MongoDB-related, mdbclient and mdb are filled in at setup_mongo_credentials. """
mongo_project_name = 'opendoge'
mongo_database_name = 'opendoge-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'
mdbclient: MongoClient = None
mdb: Database = None

""" Passed reference to facilitate wrapper-fetching. """
current_ref: str = None

""" Utilities """

def transform_to_call(target: str, is_argument: bool = False) -> str:
    """Transforms a python string to a function/argument name.

    Args:
        target (str): The target string.
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

    return f"event_{result}" if not is_argument else result

def transform_to_original(target: str) -> str:
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

def format_res(event_name: str, event_reply: str = 'Reply',**kwargs) -> dict:
    """Formats a response to be sent in an appropriate form, with optional keyword arguments.

    Args:
        event_name (str): The name of the event.
        event_reply (str): The string to concatenate to the event_name which will be the reply. Defaults to Reply.

    Returns:
        dict: The formatted response.
    """
    result_data = dict(data=kwargs, event=f'{event_name}{event_reply}', originalEvent=event_name)

    if current_ref:
        result_data['ref'] = current_ref

    return dumps(result_data)

def format_res_err(event_name: str, event_reply: str, error_message: str, is_no_event_response: bool = False, **kwargs) -> dict:
    """Same as above but for errors.

    Args:
        event_name (str): The name of the event. Set to '' so as not to pass originalEvent to the response.
        event_reply (str): The string to concatenate to the event_name which will be the reply.
        error_message (str): The message of the error.
        is_no_event_response (bool): If True, event_reply wont be concatenated to event_name. This is helpful for general errors.

    Returns:
        dict: The formatted error response.
    """

    result_data = dict(data={'errorMessage': error_message, **kwargs}, event=f'{event_name}{event_reply}' if not is_no_event_response else f'{event_reply}',
                        originalEvent=event_name)

    if current_ref:
        result_data['ref'] = current_ref

    return dumps(result_data)

def check(data: dict) -> None:
    """Checks pairs of a dictionary where the second key must denote the required type of the first one. eg: 
        
    ```check({some_expected_int_var: int})```

    Args:
        data (dict): The dictionary to check.
    """
    for item, type in data:
        assert isinstance(item, type)

def check_loop_data(data: dict, keys: List[str]):
    """Checks if a number of keys are present in a dictionary.

    Args:
        data (dict): The dictionary to check against.
        keys (List[str]): The keys which must be present the dictionary.

    Returns:
        None/str: None if the keys are present else an error string.
    """
    keys_needed = []

    for key in keys:
        if key not in data:
            keys_needed.append(transform_to_original(key))
            continue

        try:
            if len(data[key].strip()) == 0:
                return f'{transform_to_original(key)} value mustn\'t be empty.'
        except AttributeError:
            """ WebSocketServerProtocol probably, passed by default in functions which ask for it. """
            continue

    """ Much better visualization by showing them all at once. """
    if keys_needed:
        return f'Data must contain {" and ".join([key for key in keys_needed])}.'
    return None

def gen_id() -> str:
    """Generates an ID with 15 digits for use when creating an account.

    Returns:
        str: The resulting ID.
    """
    result_id = ''

    for i in range(15):
        result_id += str(choice(f"{ascii_letters}{digits}"))

    return result_id

def check_account(request_ip: str) -> bool:
    """Checks whether or not an IP is associated with an account.

    Args:
        request_ip (str): The IP of the request.

    Returns:
        bool: Whether or not it is linked to an account.
    """
    return request_ip in wss_accounts

def get_users() -> dict:
    """Returns the users which are created. Only for the database version.

    Returns:
        dict: The users dictionary.
    """

    result_users = {}

    """ Gets all ids in the users collection. """
    for cursor in mdb.users.find({}):
        del cursor['_id']
        result_users[list(cursor.keys())[0]] = list(cursor.values())[0]

    return result_users

""" Events """

def event_create_traveller(event: str, traveller_name: str, traveller_email: str, traveller_password: str, wss: WebSocketServerProtocol):
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

    if check_account(wss.remote_address[0]):
            return format_res_err(event, 'AlreadyLoggedIn', 'You are currently logged in. Logout and try again.')

    """ Remember to keep the strip methods, we need the original name. """
    if not len(traveller_name.strip()) >= MIN_ACCOUNT_NAME or not len(traveller_name.strip()) <= MAX_ACCOUNT_NAME:
        return format_res_err(event, 'NameExceedsLimit', f'Traveller name must be between {MIN_ACCOUNT_NAME} and {MAX_ACCOUNT_NAME} characters long.')

    """ Validate the email, check if it has @ and a valid domain. """
    try:
        validate_email(traveller_email)
    except EmailNotValidError as e:
        return format_res_err(event, 'EmailInvalid', str(e))

    if not len(traveller_password.strip()) >= MIN_PASS_LENGTH or not len(traveller_password.strip()) <= MAX_PASS_LENGTH:
        return format_res_err(event, 'PasswordExceedsLimit', f'Traveller password must be between {MIN_PASS_LENGTH} and {MAX_PASS_LENGTH} characters.')

    """ Prevent duplicate emails. """
    is_email_taken = False

    if IS_LOCAL:
        for key, item in travellers.items():
            if item.traveller_email == traveller_email:
                is_email_taken = True
                break
    else:
        for key, item in get_users().items():
            if item['travellerEmail'] == traveller_email:
                is_email_taken = True
                break

    if is_email_taken:
        return format_res_err(event, 'EmailInUse', 'This email is already in use by another account.')

    """ Visible by fetchTravellers and its not at all private. """
    traveller_id = gen_id()

    """ rounds=13 so as to exceed the 214ms bare limit according to: https://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256. """
    hashed_password = hashpw(bytes(traveller_password, encoding='ascii'), gensalt(rounds=13))

    if IS_LOCAL:
        travellers[traveller_id] = Traveller(traveller_id, traveller_name, traveller_email, hashed_password)
    else:
        mdb.users.insert_one({traveller_id: {'travellerName': traveller_name, 'travellerEmail': traveller_email,
                                            'travellerPassword': hashed_password}})

        """ Update registered emails and accounts links. """
    wss_accounts[wss.remote_address[0]] = traveller_id

    return format_res(event, travellerId=traveller_id)

def event_login_traveller(event: str, traveller_email: str, traveller_password: str, wss: WebSocketServerProtocol):
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

    """ Validate the email, check if it has @ and a valid domain. """
    try:
        validate_email(traveller_email)
    except EmailNotValidError as e:
        return format_res_err(event, 'EmailInvalid', str(e))

    """ Check password validity. """
    if not len(traveller_password.strip()) >= MIN_PASS_LENGTH or not len(traveller_password.strip()) <= MAX_PASS_LENGTH:
        return format_res_err(event, 'PasswordExceedsLimit', f'Traveller password must be between {MIN_PASS_LENGTH} and {MAX_PASS_LENGTH} characters.')

    """ Determine which id the email is associated with. """
    traveller_id = ''

    if IS_LOCAL:
        for key, item in travellers.items():
            if item.traveller_email == traveller_email:
                traveller_id = key
    else:
        for key, item in get_users().items():
            if item['travellerEmail'] == traveller_email:
                traveller_id = key

    if len(traveller_id) == 0:
        return format_res_err(event, 'NotFound', 'The specified traveller could not be found.')

    """ Check if the requestee is already logged into an account. """
    if check_account(wss.remote_address[0]):
        return format_res_err(event, 'AlreadyLoggedIn', 'You are currently logged in. Logout and try again.')

    """ Check if someone has already logged into this account. """
    for key, item in wss_accounts.items():
        if item == traveller_id:
            return format_res_err(event, 'AccountTaken', 'Another user has already logged into this account.')

    if checkpw(bytes(traveller_password, encoding='ascii'), travellers[traveller_id].traveller_password if IS_LOCAL
                                                            else get_users()[traveller_id]['travellerPassword']):
        """ Link the IP to an account. """
        wss_accounts[wss.remote_address[0]] = traveller_id

        return format_res(event, travellerId=traveller_id)

    return format_res_err(event, 'InvalidPassword', f'The password is invalid.')

def event_logout_traveller(event: str, wss: WebSocketClientProtocol):
    """Logs out a user from his associated traveller, if any. 
        
    Args:
        wss (WebSocketClientProtocol): The websocket client.

    Possible Responses:
        logoutTravellerReply: The IP has successfully logged out of the associated account.

        logoutTravellerNoAccount: There is no account associated with this IP address.
    """
    if wss.remote_address[0] in wss_accounts:
        del wss_accounts[wss.remote_address[0]]

        return format_res(event)
    return format_res_err(event, 'NoAccount', 'There is no account associated with this IP.')

def event_fetch_traveller(event: str, traveller_id: str):
    """Fetches a traveller's info, if he exists in the database.

    Args:
        traveller_id (str): The id of the traveller to fetch info from.

    Possible Responses:
        fetchTravellerReply: Info about a traveller has been successfully fetched.

        fetchTravellerNotFound: The traveller with the required ID could not be found.
    """
    traveller_name = ''

    if IS_LOCAL:
        if traveller_id in travellers:
            traveller_name = travellers[traveller_id].traveller_name
    else:
        if traveller_id in get_users():
            traveller_name = get_users()[traveller_id]['travellerName']

    if traveller_name:
        return format_res(event, travellerName=traveller_name, travellerId=traveller_id)
    return format_res_err(event, 'NotFound', f'Traveller with id {traveller_id} not found.')

def event_fetch_travellers(event: str):
    """Fetches every single traveller's info.
        
    Possible Responses:
        fetchTravellersReply: The existing traveller IDs have been successfully fetched.
    """
    return format_res(event, travellerIds=[id for id in travellers] if IS_LOCAL else [id for id in get_users()])

def event_total_travellers(event: str):
    """Returns the number of created traveller accounts.
        
    Possible Responses:
        totalTravellersReply: The number of existing travellers has been successfully fetched.
    """
    return format_res(event, totalTravellers=len(travellers) if IS_LOCAL else len(get_users()))

def event_online_travellers(event: str):
    """Returns the number of online travellers.
    
    Possible Responses:
        onlineTravellersReply: The number of online travellers at the moment.
    """
    return format_res(event, onlineTravellers=len(wss_accounts))

""" Main """

async def request_switcher(wss: WebSocketClientProtocol, data: dict):
    """Switches events according to the data provided.

    Args:
        wss (WebSocketClientProtocol): The client waiting for a response.
        data (dict): The data sent by the client.

    Returns:
        dict: The response according to the request. Nothing may be returned, which means the request is invalid and that __current_error should be output.

    Possible Responses:
        EventNotFound: The given event could not be found.
        EventUnknownError: There was an error processing the event.
        FormatError: The format of the error is incorrect.
    """

    """ Refuse to process dictionaries without an event key, which must be atleast 1 character long. """
    try:
        event = data['event']
        assert len(data['event']) > 0
    except:
        return

    try:
        """ Check if arguments are given. """
        target_function: function = globals()[transform_to_call(event)]
        
        target_arg_names = getfullargspec(target_function).args

        """ Keyword arguments to pass to the function. """
        target_args = {}

        for arg, value in data.items():
            if transform_to_call(arg, True) in target_arg_names:
                arg_to_add = transform_to_call(arg, True)
                    
                """ Preserve event name. """
                if arg == 'event':
                    arg_to_add = arg

                target_args[arg_to_add] = value

        """ Custom arguments to pass manually. """
        if 'wss' in target_arg_names:
            target_args['wss'] = wss

        """ Check for arguments before calling, the call may not error but some arguments may be empty. """
        args_errored = check_loop_data(target_args, target_arg_names)

        if args_errored:
            return format_res_err(event, 'FormatError', args_errored, True)

        try:
            return target_function(**target_args)
        except Exception as e:

            """ Create bug report. """
            if IS_LOCAL:
                print(exc_info()[0])
            else:
                try:
                    mdb.logs.insert_one({f'bug-{str(uuid4())}', exc_info()[0]})
                except:
                    print(f'FATAL DATABASE ERROR EXITING: \n{exc_info()[0]}')
                    exit()

            return format_res_err(event, 'EventUnknownError', 'Unknown internal server error.', True)

    except KeyError:
        """ Provide the user with the available events, in a seperate key to be able to split them. """
        possible_events = [transform_to_original(event.replace('event_', '')) for event in globals() if event.startswith('event_')]

        events_response = ''

        for index, ev in enumerate(possible_events):
            events_response = f"{events_response}{ev}|" if index + 1 < len(possible_events) else f"{events_response}{ev}"

        return format_res_err(event, 'EventNotFound', 'This event doesn\'t exist.', True, possibleEvents=events_response)

async def serve(wss: WebSocketClientProtocol, path: str) -> None:
    """Called only by websockets.serve.

    Args:
        wss (WebSocketClientProtocol): The websocket client.
        path (str): The path which the client wants to access.
    """

    global wss_accounts

    print(f'A traveller has connected. Travellers online: {len(wss_accounts)}')

    """ Set to 0 ONLY if the ip doesn't exist since previous IPs are stored even if it disconnects. """
    if wss.remote_address[0] not in ip_requests:
        ip_requests[wss.remote_address[0]] = 0

    while True:
        try:
            response = await wss.recv()

            """ Prevent malicious intents. """
            if ip_requests[wss.remote_address[0]] > IP_RATELIMIT_MAX:
                continue

            ip_requests[wss.remote_address[0]] += 1

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

            global current_ref

            """ Remember to return passed reference. """
            if 'ref' in data:
                current_ref = data['ref']

            result = await request_switcher(wss, data)

            """ If nothing is returned, skip this call. """
            if not result:
                continue

            await wss.send(result)

            global total_requests

            total_requests += 1

            result = loads(result)

            print(f"[{total_requests}] {result['originalEvent']}: {result['event']}")

            current_ref = None

        except ConnectionClosed as e:
            """ Don't remove traveller from IP requests, prevent spam. """

            """ Remove a traveller from the linked accounts list, not online anymore. Only for production servers. """
            if wss.remote_address[0] in wss_accounts and not IS_LOCAL:
                del wss_accounts[wss.remote_address[0]]

            print(f'A traveller has disconnected. Code: {e.code} | Travellers online: {len(wss_accounts)}')

            break

def setup_mongo(mongodb_username: str, mongodb_password: str) -> None:
    """Sets up the mongo database for production servers.

    Args:
        mongodb_username (str): The username of an authored user of the database.
        mongodb_password (str): The password of the authored user.
    """
    start = time()

    global mdbclient
    
    try:
        mdbclient = MongoClient(f'mongodb+srv://{mongodb_username}:{mongodb_password}@{mongo_project_name}.vevnl.mongodb.net/{mongo_database_name}?{mongo_client_extra_args}')

        global mdb

        mdb = mdbclient[mongo_database_name]

        """ Prevent cold-booting MongoDB's first request in responses, use a random collection. """
        mdb.some_random_collection.count_documents({})

        print(f'Successfully setup MongoDB in {int(round(time() - start, 2) * 1000)} ms.')
    
    except OperationFailure:
        print('Invalid username or password provided for MongoDB, exiting.')
        exit()

""" Tasks """

async def task_cleanup_ip_ratelimits() -> None:
    """Resets the IP ratelimits for every traveller. """

    while True:
        for ip in ip_requests:
            ip_requests[ip] = 0

        await asyncio.sleep(IP_RATELIMIT_CLEANUP_INTERVAL)

async def task_cleanup_ip_requests() -> None:
    """Resets the IP requests dictionary to delete cached IPs. """

    while True:
        ip_requests.clear()
        await asyncio.sleep(IP_REQUESTS_CLEANUP_INTERVAL)

async def task_cleanup_account_links() -> None:
    """Resets the accounts linked to each IP. """

    while True:
        wss_accounts.clear()
        await asyncio.sleep(IP_ACCOUNT_CLEANUP_INTERVAL)

if __name__ == '__main__':
    print(f"Server type: {'PRODUCTION' if not IS_LOCAL else 'LOCAL'}")

    """ Setup MongoDB. """
    if not IS_LOCAL:
        if not 'OPENDOGE_MONGODB_USERNAME' in environ and not 'OPENDOGE_MONGODB_PASSWORD' in environ:
            print('MongoDB variables must either be passed to the start function or set to the environmental variables: OPENDOGE_MONGODB_USERNAME, OPENDOGE_MONGODB_PASSWORD for the production server to function!')
            exit()
        else:
            setup_mongo(environ['OPENDOGE_MONGODB_USERNAME'], environ['OPENDOGE_MONGODB_PASSWORD'])

    """ Heroku expects us to bind on a specific port, if deployed locally we can bind anywhere. """
    port = environ.get('PORT', 5000)

    start_server = ws_serve(serve, '0.0.0.0', port)

    """ Dynamically find and start server tasks. """
    registered_tasks = [task for task_name, task in globals().items() if task_name.startswith('task_')]

    for task in registered_tasks:
        loop.create_task(task())

    if len(registered_tasks) > 0:
        print('Tasks started.')

    try:
        print(f'Server running at: {gethostbyname(gethostname())}:{port}')
    except gaierror:
        print(f'Server running at port: {port}')

    loop.run_until_complete(start_server)

    """ Start the infinite server loop. """
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(f'Server shut down due to an error: \n{e.__traceback__}')
