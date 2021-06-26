"""

License: GPL-3

Maintainer: Shadofer#0001

Contributors: Otterlord#3653

File description:
    The main file of the server of TowerVerse.

Extra info:
    Run this file with the command line argument -h to see available options.

    For the production server set the following environmental variables for MongoDB and Email functions(emails should be enabled for local development aswell):

        TOWERVERSE_EMAIL_ADDRESS: The email address to send emails with,
        TOWERVERSE_EMAIL_PASSWORD: The password of the email address,
        TOWERVERSE_MONGODB_USERNAME: The username of an authored user of your MongoDB,
        TOWERVERSE_MONGODB_PASSWORD: The password of the authored user.

"""

""" Get the time for imports to be loaded. """
from time import time

imports_start_time = time()

""" BUILT-IN MODULES """
import asyncio

""" Command-line options. """
from argparse import ArgumentParser

""" For hosting. """
from os import environ

""" Formatting responses. """
from json import dumps, loads
from json.decoder import JSONDecodeError

""" Getting hosting info. """
from socket import gethostbyname, gethostname

""" Specifying variable types. """
from typing import Callable, Dict, List, Set

""" Checking letters. """
from string import whitespace

""" Inspect functions. """
from inspect import getfullargspec

""" To prevent a simple exception at startup. """
from socket import gaierror

""" Generating account hashes. """
from uuid import uuid4

""" Logging levels. """
from logging import StreamHandler, getLogger

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

import towerverseserver.utils as utils
from towerverseserver.classes import *
from towerverseserver.constants import *

""" Setup optional command-line arguments. """
parser = ArgumentParser(description='The main file of the server of TowerVerse.')

parser.add_argument('--local', help='This option should be passed whenever the server is developed locally. With this option, the server makes use of runtime variables rather than MongoDB. Small reminder that this option still requires that email environmental variables be set.', action='store_true')
parser.add_argument('--test', help='This option disables removing IP account links between disconnects to facilitate pytest. Most of the time, it shouldn\'t be used for anything else. This option must be used with --local.', action='store_true')
parser.add_argument('--log', help='Specifies the level of logging where: 10 Verbose 20 Info 30 Warning 40 Error 50 Silent. Defaults to 10.', type=int, default=10, choices=[10, 20, 30, 40, 50])

parser_args = parser.parse_args()

""" Used to print logs. """
logHandler = StreamHandler()

""" Available by other scripts aswell. """
log = getLogger(LOGGER_NAME)

log.setLevel(parser_args.log)

""" Silent, ignore handler. """
if not parser_args.log == 50:
    log.addHandler(logHandler)

log.info(f'Modules loaded in {int(round(time() - imports_start_time, 2) * 1000)} ms.')

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

""" Accounts linked to IPs. """
wss_accounts: Dict[str, str] = {}

""" Accounts to create when verified. """
accounts_to_create: Dict[str, TempTraveller] = {}

""" Whether or not this is a locally-hosted server. """
IS_LOCAL = parser_args.local

""" Used to facilitate, do not use this for prod/testing dev. Rather, use it with pytest. """
IS_TEST = parser_args.test

""" MongoDB-related, filled in at setup_mongo. """
mdbclient: MongoClient = None
mdb: Database = None

""" Passed reference to facilitate wrapper-fetching. """
current_ref: str = None

""" Email-related, filled in at setup_email. """
email_smtp: SMTP = None

""" Account-only events. These are only used if the requestee is logged in to an account, otherwise an error is thrown. Filled in with the account_only decorator. """
account_events: Dict[str, Callable] = {}

""" No-account-events. These are only used if the requestee is NOT logged in to an account, otherwise an error is thrown. Filled in with the no_account_only decorator. """
no_account_events: Dict[str, Callable] = {}

""" List of all decorators, checked by request_switcher. """
decorators_list: Set[str] = set({'account', 'no_account'})

""" Utilities which need server variables to work. """

def format_res(event_name: str, event_reply: str = 'Reply', **kwargs) -> dict:
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

def format_res_err(event_name: str, event_reply: str, error_message: str, is_no_event_response: bool = False, no_original_event: bool = False, **kwargs) -> dict:
    """Same as above but for errors.

    Args:
        event_name (str): The name of the event. Set to '' so as not to pass originalEvent to the response.
        event_reply (str): The string to concatenate to the event_name which will be the reply.
        error_message (str): The message of the error.
        is_no_event_response (bool): If True, event_reply wont be concatenated to event_name. This is helpful for general errors.
        no_original_event (bool): Whether or not the originalEvent key should be provided. Useful when you can't make it out.

    Returns:
        dict: The formatted error response.
    """

    result_data = dict(data={'errorMessage': error_message, **kwargs}, event=f'{event_name}{event_reply}'
                                                                        if not is_no_event_response
                                                                        else f'{event_reply}')

    if current_ref:
        result_data['ref'] = current_ref

    if not no_original_event:
        result_data['originalEvent'] = event_name

    return dumps(result_data)

def has_account(request_ip: str) -> bool:
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
        utils.log_error('Invalid email provided to send_email, aborting operation', e)

""" Decorators and checks. """

def account(event: Callable):
    """Decorator. Marks an event as only accessible with an account. Overwrites duplicates. Must be passed without transforming the event name first.

    Args:
        event (Callable): The event to mark.
    """

    def wrapper(event: Callable):

        name = event.__name__

        """ Don't mind if it overwrites another one, just warn. """
        if name in account_events:
            log.warn(f'The event name {name} is already in account_events. Consider checking for duplicates to prevent possible errors.')

        account_events[name] = event

    return wrapper(event)

def account_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """account_only decorator check. """
    if not has_account(wss.remote_address[0]):
        return format_res_err(event, 'AccountOnly', 'You must login to an account first before using this event.', True)

def no_account(event: Callable):
    """Decorator. Marks an event as only accessible without an account. Overwrites duplicates. Must be passed without transforming the event name first.

    Args:
        event (Callable): The event to mark.
    """

    def wrapper(event: Callable):

        name = event.__name__

        if name in no_account_events:
            log.warn(f'The event name {name} is already in no_account_events. Consider checking for duplicates to prevent possible errors.')

        no_account_events[name] = event

    return wrapper(event)

def no_account_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """ no_account_only decorator check. """
    if has_account(wss.remote_address[0]):
        return format_res_err(event, 'NoAccountOnly', 'You must logout of your current account first before using this event.', True)

""" Events """

@no_account
def event_create_traveller(event: str, traveller_name: str, traveller_email: str, traveller_password: str):
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
        createTravellerNameBadFormat: The name of the account contains invalid characters.
        createTravellerEmailBadFormat: The email of the account contains invalid characters.
    """

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

    traveller_password = utils.format_password(traveller_password)

    """ Pass all the password checks and return if there's an error returned. """
    traveller_password_checks = utils.check_password(traveller_password)

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

    """ Also check in travellers who are awaiting authentication. """
    for key, item in accounts_to_create.items():
        if item.traveller_email == traveller_email:
            is_email_taken = True
            break

    if is_email_taken:
        return format_res_err(event, 'EmailInUse', 'This email is already in use by another account.')

    """ Visible by fetchTravellers and its not at all private. """
    traveller_id = utils.gen_id() if not IS_TEST else '123'

    """ rounds=13 so as to exceed the 214ms bare limit according to: https://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256. """
    hashed_password = hashpw(bytes(traveller_password, encoding='ascii'), gensalt(rounds=13))

    """ Add the account to a temporary dictionary until it's verified. Also generate the target verification code. """
    traveller_verification = utils.gen_verification_code() if not IS_TEST else '123456'

    accounts_to_create[traveller_id] = TempTraveller(traveller_id, traveller_name, traveller_email, hashed_password, traveller_verification)

    """ Send email verification code, doesn't need to block. Don't do this for tests. """
    if not IS_TEST:
        loop.create_task(send_email(traveller_email, 'GateVerse verification code', [f'This is your email verification code: {traveller_verification}']))

    return format_res(event, travellerId=traveller_id)

@no_account
def event_login_traveller(event: str, traveller_email: str, traveller_password: str, wss: WebSocketServerProtocol):
    """Logs in a websocket connection to a traveller account.

    Args:
        traveller_email (str): The traveller account's email to login to.
        traveller_password (str): The traveller account's password to check against.

    Possible Responses:
        loginTravellerReply: The websocket has successfully connected to a traveller. No additional keys have to be passed for future account-related methods.

        loginTravellerNotFound: The traveller with the required ID could not be found.
        loginTravellerInvalidPassword: The given password doesn't match the original one.
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
    traveller_password_checks = utils.check_password(traveller_password)

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
    
        """ Link the IP to an account. """
        wss_accounts[wss.remote_address[0]] = traveller_id

        return format_res(event, travellerId=traveller_id)

    return format_res_err(event, 'InvalidPassword', f'The password is invalid.')

@no_account
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
        return format_res_err(event, 'CodeExceedsLimit', f'The verification code must consist of exactly {VERIFICATION_CODE_LENGTH} characters.')

@account
def event_logout_traveller(event: str, wss: WebSocketClientProtocol):
    """Logs out a user from his associated traveller account. 

    Possible Responses:
        logoutTravellerReply: The IP has been successfully unliked from its associated account.
    """
    del wss_accounts[wss.remote_address[0]]

    return format_res(event)

@account
def event_fetch_travellers(event: str):
    """Fetches every single traveller's info.
        
    Possible Responses:
        fetchTravellersReply: The existing traveller IDs have been successfully fetched.
    """
    return format_res(event, travellerIds=[id for id in travellers] if IS_LOCAL else [id for id in get_users()])

@account
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

@account
def event_total_travellers(event: str):
    """Returns the number of created traveller accounts.
        
    Possible Responses:
        totalTravellersReply: The number of existing travellers has been successfully fetched.
    """
    return format_res(event, totalTravellers=len(travellers) if IS_LOCAL else len(get_users()))

@account
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
        FormatError: The format of the request is incorrect.
        EventEmpty: The event key is empty.

        Decorator checks:
            AccountOnly: The requested event requires that this IP be associated with an account.
            NoAccountOnly: The requested event requires that this IP NOT be associated with an account.
    """

    """ Refuse to process dictionaries without an event key, which must be atleast 1 character long. """
    try:
        event = data['event']
        assert len(data['event']) > 0
    except (KeyError, AssertionError):
        return format_res_err('', 'EventEmpty', 'The event key is empty or it isn\'t provided.', True, True)

    """ Transform it early on. """
    transformed_event = utils.transform_to_call(event)

    """ Find the function first to run some checks. """
    target_function: function = None
    
    """ Check if it's in one of the decorator lists which prohibit access. Don't pass the transformed one. """
    for decorator in decorators_list:

        """ Find if the requested event is in one of the decorators. """
        decorator_events = dict(globals())[f'{decorator}_events']
        
        if transformed_event in decorator_events:

            """ Found, run checks. """
            decorator_check_func = dict(globals())[f'{decorator}_check']

            decorator_check_args = {'event': event}

            """ Pass requested client. """
            if 'wss' in getfullargspec(decorator_check_func).args:
                decorator_check_args['wss'] = wss

            decorator_check_result = decorator_check_func(**decorator_check_args)

            """ If it has returned something, it should be formatted already to be sent right back to the requestee as an error. """
            if decorator_check_result:
                return decorator_check_result

            """ If it has passed, go on to assign the function to call. """
            target_function = decorator_events[transformed_event]

    if not target_function:
        """ Events MUST contain one decorator or the other, throw an error. """
        return format_res_err(event, 'EventNotFound', 'This event doesn\'t exist.', True)

    """ Check if arguments are given. """
    target_arg_names = getfullargspec(target_function).args

    """ Keyword arguments to pass to the function. """
    target_args = {}

    for arg, value in data.items():
        if utils.transform_to_call(arg, True) in target_arg_names:
            arg_to_add = utils.transform_to_call(arg, True)
                
            """ Preserve event name. """
            if arg == 'event':
                arg_to_add = arg

            target_args[arg_to_add] = value

    """ Custom arguments to pass manually. """
    if 'wss' in target_arg_names:
        target_args['wss'] = wss

    """ Check for arguments before calling, the call may not error but some arguments may be empty. """
    args_errored = utils.check_loop_data(target_args, target_arg_names)

    if args_errored:
        return format_res_err(event, 'FormatError', args_errored, True)

    try:
        return target_function(**target_args)
    except Exception as e:

        """ Create bug report. """
        if IS_LOCAL or IS_TEST:
            utils.log_error(f'Error occured while calling {event}', e)
        else:
            try:
                mdb.logs.insert_one({f'bug-{str(uuid4())}': f'{e.__class__.__name__}{e}'})
            except:
                utils.log_error_and_exit('Fatal database error', e)

        return format_res_err(event, 'EventUnknownError', 'Unknown internal server error.', True)

async def serve(wss: WebSocketClientProtocol, path: str) -> None:
    """Called only by websockets.serve.

    Args:
        wss (WebSocketClientProtocol): The websocket client.
        path (str): The path which the client wants to access.

    Possible Responses:
        JSONFormatError: The request contains invalid JSON.
        RatelimitError: The IP has reached the max requests allowed at a specified time length.
    """

    global wss_accounts

    log.info(f'A traveller has connected. Travellers online: {len(wss_accounts)}')

    """ Set to 0 ONLY if the ip doesn't exist since previous IPs are stored even if it disconnects. """
    if wss.remote_address[0] not in ip_requests:
        ip_requests[wss.remote_address[0]] = 0

    while True:
        try:
            response = await wss.recv()

            result = ''

            """ Prevent malicious intents. """
            if ip_requests[wss.remote_address[0]] > IP_RATELIMIT_MAX:

                """ Send it in-place, dont allow it to go further into request_switcher. """
                await wss.send(format_res_err('', 'RatelimitError', 'You are ratelimited.', True, True))
                continue

            ip_requests[wss.remote_address[0]] += 1

            """ Don't even handle empty requests, only ratelimit them. """
            if len(response.strip()) == 0:
                continue

            """ Determine data validity. """
            try:
                data = loads(response)

                assert isinstance(data, dict)
                
                """ Prevent strange values. """
                for key, item in data.items():
                    assert isinstance(key, str)
                    assert isinstance(item, str)

            except (JSONDecodeError, AssertionError):
                result = format_res_err('', 'JSONFormatError', 'The request contains invalid JSON.', True, True)

            """ Send the premature error straight away to prevent errors with data later on. """
            if result:
                await wss.send(result)
                continue

            global current_ref

            """ Remember to return passed reference. """
            if 'ref' in data:
                current_ref = data['ref']

            """ Check for previous responses. """
            if not result:
                result = await request_switcher(wss, data)

            """ If nothing is returned, skip this call. """
            if not result:
                continue

            await wss.send(result)

            global total_requests

            total_requests += 1

            result = loads(result)

            try:
                log.info(f"[{total_requests}] {result['originalEvent']}: {result['event']}")
            except KeyError:
                log.info(f'[{total_requests}] Invalid JSON request provided.')

            current_ref = None

        except ConnectionClosed as e:
            """ Don't remove traveller from IP requests, prevent spam. """

            """ Remove a traveller from the linked accounts list, not online anymore. Only for production servers. """
            if has_account(wss.remote_address[0]) and not IS_LOCAL:
                del wss_accounts[wss.remote_address[0]]

            log.info(f'A traveller has disconnected. Code: {e.code} | Travellers online: {len(wss_accounts)}')

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

        log.info(f'Successfully setup MongoDB in {int(round(time() - start, 2) * 1000)} ms.')
    
    except OperationFailure:
        log.error('Invalid username or password provided for MongoDB, exiting.')
        exit()

    except ConfigurationError:
        log.error('The TowerVerse database may be temporarily down, exiting.')
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
        utils.log_error_and_exit('Error in setup_email', e)

    global email_smtp
    email_smtp = SMTP(email_address, email_password)
    
    log.info('Successfully setup email account.')

""" Tasks """

async def task_cleanup_ip_ratelimits() -> None:
    """ SETS every key found in the ip_requests dictionary to 0. """

    while True:
        for ip in ip_requests:
            ip_requests[ip] = 0

        await asyncio.sleep(IP_RATELIMIT_CLEANUP_INTERVAL)

async def task_cleanup_ip_requests() -> None:
    """ CLEARS every key found in the ip_requests dictionary. """

    while True:
        ip_requests.clear()
        await asyncio.sleep(IP_REQUESTS_CLEANUP_INTERVAL)

async def task_cleanup_account_links() -> None:
    """ CLEARS the linked IPs and accounts dictionary. """

    while True:
        wss_accounts.clear()
        await asyncio.sleep(IP_ACCOUNT_CLEANUP_INTERVAL)

async def task_cleanup_temp_accounts() -> None:
    """ DELETES accounts which have not been verified. """
    
    while True:
        accounts_to_create.clear()
        await asyncio.sleep(TEMP_ACCOUNT_CLEANUP_INTERVAL)

""" Entry point. """
if __name__ == '__main__':

    server_type = 'PRODUCTION'
    
    if IS_LOCAL:
        server_type = 'LOCAL'
    
    if IS_TEST:
        server_type = 'TEST'
        
    log.info(f'Server type: {server_type}')

    if not IS_TEST:
        if not 'TOWERVERSE_EMAIL_ADDRESS' in environ or not 'TOWERVERSE_EMAIL_PASSWORD' in environ:
            log.error('Environmental variables TOWERVERSE_EMAIL_ADDRESS and TOWERVERSE_EMAIL_PASSWORD must be set in order for email capabilities to function, exiting.')
            exit()
        else:
            setup_email(environ['TOWERVERSE_EMAIL_ADDRESS'], environ['TOWERVERSE_EMAIL_PASSWORD'])
            
        """ Setup MongoDB. """
        if not IS_LOCAL:
            if not 'TOWERVERSE_MONGODB_USERNAME' in environ or not 'TOWERVERSE_MONGODB_PASSWORD' in environ:
                log.error('Environmental variables TOWERVERSE_MONGODB_USERNAME and TOWERVERSE_MONGODB_PASSWORD must be set in order for email capabilities to function, exiting.')
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
        log.info('Tasks started.')

    try:
        loop.run_until_complete(start_server)
    except Exception as e:
        utils.log_error_and_exit('Server failed to start', e)

    try:
        log.info(f'Server running at: {gethostbyname(gethostname())}:{port}')
    except gaierror:
        log.info(f'Server running at port: {port}')

    """ Start the infinite server loop. """
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        utils.log_error_and_exit('Server shut down due to an error', e)
