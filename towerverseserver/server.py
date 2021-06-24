"""

License: GPL-3

Maintainer: Shadofer#0001

Contributors: Otterlord#3653

File description:
    The main file of the server of TowerVerse.

Extra info:
    Pass --local in order to disable database-related methods and --test to use it with pytest.

    Otherwise set the following environmental variables for MongoDB and Email functions:

        TOWERVERSE_EMAIL_ADDRESS: The email address to send emails with,
        TOWERVERSE_EMAIL_PASSWORD: The password of the email address,
        TOWERVERSE_MONGODB_USERNAME: The username of an authored user of your MongoDB,
        TOWERVERSE_MONGODB_PASSWORD: The password of the authored user.

"""

""" BUILT-IN MODULES """
import asyncio

""" For hosting. """
from os import environ

""" Formatting responses. """
from json import dumps, loads
from json.decoder import JSONDecodeError

""" Getting hosting info. """
from socket import gethostbyname, gethostname

""" Specifying variable types. """
from typing import Dict, List

""" Generating account IDs. """
from random import choice
from string import ascii_letters, ascii_uppercase, digits, whitespace

""" Inspect functions. """
from inspect import getfullargspec

""" To prevent a simple exception at startup. """
from socket import gaierror

""" Performance reports. """
from time import time

""" Generating account hashes. """
from uuid import uuid4

""" Getting command-line arguments. """
from sys import argv

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets import serve as ws_serve
from websockets.client import WebSocketClientProtocol
from websockets.exceptions import ConnectionClosed
from websockets.legacy.server import WebSocketServerProtocol

""" Email validation. """
from email_validator import EmailNotValidError, validate_email

""" Password hashing. """
from bcrypt import checkpw, gensalt, hashpw

""" MongoDB. """
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConfigurationError, OperationFailure

""" Email verification and more. """
from aioyagmail import SMTP

""" LOCAL MODULES """

from towerverseserver.classes import *

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
IP_REQUESTS_CLEANUP_INTERVAL = 60 * 60 # every minute

""" Seconds between resetting IP account links. """
IP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24 # every day

""" Seconds between resetting accounts which aren't verified. """
TEMP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24 * 7 # every week

""" Account-related. """
ACCOUNT_CHARACTERS = f'{ascii_letters}{digits}!^* '
MIN_ACCOUNT_LENGTH = 3
MAX_ACCOUNT_LENGTH = 20

EMAIL_CHARACTERS = f'{ascii_letters}{digits}@.'
MIN_EMAIL_LENGTH = 10
MAX_EMAIL_LENGTH = 60

MIN_PASS_LENGTH = 10
MAX_PASS_LENGTH = 50

VERIFICATION_CODE_LENGTH = 6

""" Accounts linked to IPs. """
wss_accounts: Dict[str, str] = {}

""" Accounts to create when verified. """
accounts_to_create: Dict[str, TempTraveller] = {}

""" Whether or not this is a locally-hosted server. """
IS_LOCAL = '--local' in argv

""" Used to facilitate, do not use this for prod/testing dev. Rather, use it with pytest. """
IS_TEST = '--test' in argv

""" MongoDB-related, mdbclient and mdb are filled in at setup_mongo. """
mongo_project_name = 'towerverse.kx1he'
mongo_database_name = 'towerverse-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'
mdbclient: MongoClient = None
mdb: Database = None

""" Passed reference to facilitate wrapper-fetching. """
current_ref: str = None

""" Email-related, filled in at setup_email. """
email_smtp: SMTP = None

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
        result_id += str(choice(f'{ascii_letters}{digits}'))

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

def gen_verification_code() -> str:
    """Generates a verification code with length VERIFICATION_CODE_LENGTH.

    Returns:
        str: The verification code.
    """
    
    verification_code = ''
    
    for i in range(VERIFICATION_CODE_LENGTH):
        verification_code += str(choice(digits))

    return verification_code

async def send_email(to: str, title: str, content: List[str]) -> None:
    """Sends an email, asynchronously.

    Args:
        to (str): The recipient of the email.
        title (str): The title of the email.
        content (List[str]): The content of the email. 1: Body, 2: Custom html, 3: An image.
    """    
    try:
        validate_email(to)
        email_smtp.send(to, title, content)
    except EmailNotValidError as e:
        print_error('Invalid email provided to send_email, aborting operation', e)

def print_error(print_msg: str, exc: Exception) -> None:
    """Prints an error and continues normal execution of the program.

    Args:
        print_msg (str): The message to print.
        exc (Exception): The exception to print below the print_msg.
    """
    if isinstance(exc, Exception):
        print(f'{print_msg}: \n{exc.__class__.__name__}{exc}')
    else:
        print('Invalid exception passed to print_error, aborting operation.')

def print_error_and_exit(exit_msg: str, exc: Exception) -> None:
    """Prints an error and forcefully exits program execution. ONLY FOR DESTRUCTIVE EXCEPTIONS.

    Args:
        exit_msg (str): The message to print.
        exc (Exception): The exception to print below the exit_msg.
    """
    if isinstance(exc, Exception):
        print(f'{exit_msg}, exiting: \n{exc.__class__.__name__}: {exc}')
        exit()
    else:
        print('Invalid exception passed to print_error_and_exit, aborting operation.')

def format_password(password: str) -> str:
    """Formats a provided password for checking later on with check_password.

    Args:
        password (str): The target password.

    Returns:
        str: The formatted password.
    """

    """ Get the version without spaces L/R. """
    password = password.strip()

    """ Remove extra whitespace. """
    temp_password = ''

    for letter in password:
        if letter not in whitespace:
            temp_password += letter

    password = temp_password

    return password

def check_password(password: str) -> list:
    """Tests a password with multiple cases. Should be used in combination with format_password.

    Args:
        password (str): The target password.

    Returns:
        list: The error, if one occured where: [0] the name of the error and [1] the description of the error.
    """
    if not len(password) >= MIN_PASS_LENGTH or not len(password) <= MAX_PASS_LENGTH:
        return ['PasswordExceedsLimit', f'Traveller password must be between {MIN_PASS_LENGTH} and {MAX_PASS_LENGTH} characters long.']

""" Events """

def event_create_traveller(event: str, traveller_name: str, traveller_email: str, traveller_password: str, wss: WebSocketServerProtocol):
    """Schedules an account for creation, after it's verified with verifyTraveller.

    Args:
        traveller_name (str): The name of the traveller.
        traveller_email (str): The email of the traveller.
        traveller_password (str): The password of the traveller.

    Possible Responses:
        createTravellerReply: The websocket has successfully created a traveller. No additional hashes have to be passed for future account-related methods.

        createTravellerEmailInvalid: The provided email is not formatted correctly.
        createTravellerEmailInUse: The provided email is already in use.
        createTravellerNameExceedsLimit: The provided name exceeds the current name length limitations.
        createTravellerEmailExceedsLimit: The provided name exceeds the current email length limitations.
        createTravellerPasswordExceedsLimit: The provided password exceeds the current password length limitations.
        createTravellerAlreadyLoggedIn: The IP is already logged in to another account.
        createTravellerNameBadFormat: The name of the account contains invalid characters.
        createTravellerEmailBadFormat: The email of the account contains invalid characters.
    """

    if check_account(wss.remote_address[0]):
            return format_res_err(event, 'AlreadyLoggedIn', 'You are currently logged in. Logout and try again.')

    """ Remember to keep the strip methods, we need the original traveller name. """
    if not len(traveller_name.strip()) >= MIN_ACCOUNT_LENGTH or not len(traveller_name.strip()) <= MAX_ACCOUNT_LENGTH:
        return format_res_err(event, 'NameExceedsLimit', f'Traveller name must be between {MIN_ACCOUNT_LENGTH} and {MAX_ACCOUNT_LENGTH} characters long.')

    """ Validate the email, check if it has @ and a valid domain. Also check its length. We need the stripped down version. """
    traveller_email = traveller_email.strip()
    if not len(traveller_email) >= MIN_EMAIL_LENGTH or not len(traveller_email) <= MAX_EMAIL_LENGTH:
        return format_res_err(event, 'EmailExceedsLimit', f'Traveller email must be between {MIN_EMAIL_LENGTH} and {MAX_EMAIL_LENGTH} characters long.')
    
    try:
        validate_email(traveller_email)
    except EmailNotValidError as e:
        return format_res_err(event, 'EmailInvalid', str(e))

    traveller_password = format_password(traveller_password)

    """ Pass all the password checks and return if there's an error returned. """
    traveller_password_checks = check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    """ Character checks. """
    for letter in traveller_name:
        if letter not in ACCOUNT_CHARACTERS:
            return format_res_err(event, 'NameBadFormat', f'The name of the account contains invalid characters.')
    
    for letter in traveller_email:
        if letter not in EMAIL_CHARACTERS:
            return format_res_err(event, 'EmailBadFormat', f'The email of the account contains invalid characters.')

    """ Prevent duplicate emails. """
    is_email_taken = False

    """ Check in both db and local variables. """
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

    """ Also check in travellers which are awaiting authentication. """
    for key, item in accounts_to_create.items():
        if item.traveller_email == traveller_email:
            is_email_taken = True
            break

    if is_email_taken:
        return format_res_err(event, 'EmailInUse', 'This email is already in use by another account.')

    """ Visible by fetchTravellers and its not at all private. """
    traveller_id = gen_id() if not IS_TEST else '123'

    """ rounds=13 so as to exceed the 214ms bare limit according to: https://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256. """
    hashed_password = hashpw(bytes(traveller_password, encoding='ascii'), gensalt(rounds=13))

    """ Add the account to a temporary dictionary until it's verified. Also generate the target verification code. """
    traveller_verification = gen_verification_code() if not IS_TEST else '123456'
    accounts_to_create[traveller_id] = TempTraveller(traveller_id, traveller_name, traveller_email, hashed_password, traveller_verification)

    """ Send email verification code, doesn't need to block. Don't do this for tests. """
    if not IS_TEST:
        loop.create_task(send_email(traveller_email, 'GateVerse verification code', [f'This is your email verification code: {traveller_verification}']))

    return format_res(event, travellerId=traveller_id)

def event_login_traveller(event: str, traveller_email: str, traveller_password: str, wss: WebSocketServerProtocol):
    """Logs in a websocket connection to a traveller account.

    Args:
        traveller_email (str): The traveller account's email to login to.
        traveller_password (str): The traveller account's password to check against.

    Possible Responses:
        loginTravellerReply: The websocket has successfully connected to a traveller. No additional keys have to be passed for future account-related methods.

        loginTravellerNotFound: The traveller with the required ID could not be found.
        loginTravellerInvalidPassword: The given password doesn't match the original one.
        loginTravellerAlreadyLoggedIn: The requestee is already logged into an account.
        loginTravellerAccountTaken: The target account is already taken by another IP.
        loginTravellerPasswordExceedsLimit: The provided password exceeds current password length limitations.
        loginTravellerEmailBadFormat: The email of the account contains invalid characters.
    """

    """ Validate the email, check if it has @ and a valid domain. """
    try:
        validate_email(traveller_email)
    except EmailNotValidError as e:
        return format_res_err(event, 'EmailInvalid', str(e))

    """ We need the stripped down version here aswell. """
    traveller_password = traveller_password.strip()

    """ Remove extra whitespace. """
    temp_traveller_password = ''

    for letter in traveller_password:
        if letter not in whitespace:
            temp_traveller_password += letter

    traveller_password = temp_traveller_password

    """ Pass all the password checks and return if there's an error returned. """
    traveller_password_checks = check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    """ Check invalid characters.  """
    for letter in traveller_email:
        if letter not in EMAIL_CHARACTERS:
            return format_res_err(event, 'EmailBadFormat', f'The email of the account contains invalid characters.')

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

    if checkpw(bytes(traveller_password, encoding='ascii'), travellers[traveller_id].traveller_password if IS_LOCAL
                                                        else get_users()[traveller_id]['travellerPassword']):
        """ Check if someone has already logged into this account. """
        for key, item in wss_accounts.items():
            if item == traveller_id:
                return format_res_err(event, 'AccountTaken', 'Another user has already logged into this account.')
        
        """ Check if the requestee is already logged into an account. """
        if check_account(wss.remote_address[0]):
            return format_res_err(event, 'AlreadyLoggedIn', 'You are currently logged in. Logout and try again.')
    
        """ Link the IP to an account. """
        wss_accounts[wss.remote_address[0]] = traveller_id

        return format_res(event, travellerId=traveller_id)

    return format_res_err(event, 'InvalidPassword', f'The password is invalid.')

def event_logout_traveller(event: str, wss: WebSocketClientProtocol):
    """Logs out a user from his associated traveller, if any. 

    Possible Responses:
        logoutTravellerReply: The IP has successfully logged out of the associated account.

        logoutTravellerNoAccount: There is no account associated with this IP address.
    """
    if check_account(wss.remote_address[0]):
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

def event_verify_traveller(event: str, traveller_id: str, traveller_code: str, wss: WebSocketServerProtocol):
    """Verifies a traveller account, if present and the code is correct.

    Args:
        traveller_id (str): The traveller id of whom to verify the email.
        traveller_code (str): The traveller verification code.

    Possible Responses:
        verifyTravellerReply: The email of the traveller has been successfully verified.
        
        verifyTravellerNotFound: The specified traveller could not be found.
        verifyTravellerInvalidCode: The provided code is invalid.
        verifyTravellerCodeExceedsLimit: The code's length is not VERIFICATION_CODE_LENGTH.
    """
    
    if traveller_id not in accounts_to_create:
        return format_res_err(event, 'NotFound', 'The specified traveller account could not be found.')

    if len(traveller_code) == VERIFICATION_CODE_LENGTH:
        if accounts_to_create[traveller_id].traveller_code == traveller_code:
            
            target_acc = accounts_to_create[traveller_id]
            
            """ Actually create the account here and link. """
            if IS_LOCAL:
                travellers[traveller_id] = Traveller(target_acc.traveller_id, target_acc.traveller_name, target_acc.traveller_email, target_acc.traveller_password)
            else:
                mdb.users.insert_one({traveller_id: {'travellerName': target_acc.traveller_name, 'travellerEmail': target_acc.traveller_email,
                                                'travellerPassword': target_acc.traveller_password}})
            
            wss_accounts[wss.remote_address[0]] = traveller_id    
            
            """ Remove the created account from the temp list. """
            del accounts_to_create[traveller_id]
            
            return format_res(event, travellerId=traveller_id)
        else:
            return format_res_err(event, 'InvalidCode', 'The provided code is invalid.')
    else:
        return format_res_err(event, 'CodeExceedsLimit', f'The verification code must be exactly {VERIFICATION_CODE_LENGTH} characters.')

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
            if IS_LOCAL or IS_TEST:
                print_error(f'Error occured while calling {event}', e)
            else:
                try:
                    mdb.logs.insert_one({f'bug-{str(uuid4())}': f'{e.__class__.__name__}{e}'})
                except:
                    print_error_and_exit('Fatal database error', e)

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
            if check_account(wss.remote_address[0]) and not IS_LOCAL:
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
        mdbclient = MongoClient(f'mongodb+srv://{mongodb_username}:{mongodb_password}@{mongo_project_name}.mongodb.net/?{mongo_client_extra_args}')

        global mdb

        mdb = mdbclient[mongo_database_name]

        """ Prevent cold-booting MongoDB's first request in responses, use a random collection. """
        mdb.some_random_collection.count_documents({})

        print(f'Successfully setup MongoDB in {int(round(time() - start, 2) * 1000)} ms.')
    
    except OperationFailure:
        print('Invalid username or password provided for MongoDB, exiting.')
        exit()

    except ConfigurationError:
        print('The TowerVerse database may be temporarily down, exiting.')
        exit()

def setup_email(email_address: str, email_password: str) -> None:
    """Sets up the account to use when sending emails.

    Args:
        email (str): The target email.
        password (str): The email's password.
    """
    try:
        validate_email(email_address)
    except EmailNotValidError as e:
        print_error_and_exit('Error in setup_email', e)

    global email_smtp
    email_smtp = SMTP(email_address, email_password)
    print('Successfully setup email account.')

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

async def task_cleanup_temp_accounts() -> None:
    """ Deletes accounts which have not been verified. """
    
    while True:
        accounts_to_create.clear()
        await asyncio.sleep(TEMP_ACCOUNT_CLEANUP_INTERVAL)

if __name__ == '__main__':
    server_type = 'PRODUCTION'
    
    if IS_LOCAL:
        server_type = 'LOCAL'
    
    if IS_TEST:
        server_type = 'TEST'
        
    print(f'Server type: {server_type}')

    if not IS_TEST:
        if not 'TOWERVERSE_EMAIL_ADDRESS' in environ or not 'TOWERVERSE_EMAIL_PASSWORD' in environ:
            print('Environmental variables TOWERVERSE_EMAIL_ADDRESS and TOWERVERSE_EMAIL_PASSWORD must be set in order for email capabilities to function, exiting.')
            exit()
        else:
            setup_email(environ['TOWERVERSE_EMAIL_ADDRESS'], environ['TOWERVERSE_EMAIL_PASSWORD'])
            
        """ Setup MongoDB. """
        if not IS_LOCAL:
            if not 'TOWERVERSE_MONGODB_USERNAME' in environ or not 'TOWERVERSE_MONGODB_PASSWORD' in environ:
                print('Environmental variables TOWERVERSE_MONGODB_USERNAME and TOWERVERSE_MONGODB_PASSWORD must be set in order for email capabilities to function, exiting.')
                exit()
            else:
                setup_mongo(environ['TOWERVERSE_MONGODB_USERNAME'], environ['TOWERVERSE_MONGODB_PASSWORD'])

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
        loop.run_until_complete(start_server)
    except Exception as e:
        print_error_and_exit('Server failed to start', e)

    try:
        print(f'Server running at: {gethostbyname(gethostname())}:{port}')
    except gaierror:
        print(f'Server running at port: {port}')

    """ Start the infinite server loop. """
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print_error_and_exit('Server shut down due to an error', e)
