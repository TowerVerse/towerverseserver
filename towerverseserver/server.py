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
from time import gmtime, time

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

""" Inspect functions. """
from inspect import getfullargspec

""" To prevent a simple exception at startup. """
from socket import gaierror

""" Generating account hashes. """
from uuid import uuid4

""" Logging levels. """
from logging import StreamHandler, getLogger
from time import strftime

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets import serve as ws_serve
from websockets.client import WebSocketClientProtocol
from websockets.exceptions import ConnectionClosed
from websockets.legacy.server import WebSocketServerProtocol

""" Password hashing. """
from bcrypt import checkpw, gensalt, hashpw

""" MongoDB-related. """
from bson.objectid import ObjectId
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

logHandler = StreamHandler()

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

""" List of all tasks to run. """
tasks_list: Dict[str, Callable] = {}

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
    """Same as format_res but for errors.

    Args:
        event_name (str): The name of the event. 
        event_reply (str): The string to concatenate to the event_name which will be the reply.
        error_message (str): The message of the error.
        is_no_event_response (bool): If True, event_reply wont be concatenated to event_name. This is helpful for general errors.
        no_original_event (bool): Whether or not the originalEvent key should be provided. Useful when you can't make the event out.

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

def get_users(pure: bool = False) -> Dict[str, Traveller]:
    """Returns the users which are created. Only for the database version. 

    Args:
        pure (bool): Whether or not a Traveller should be returned otherwise the raw data will be.

    Returns:
        Dict[str, Traveller]: The users dictionary.
    """

    result_users: Dict[str, Traveller] = {}

    for cursor in mdb.users.find({}):
        user_dict = list(cursor.values())[1]
        user_id = list(cursor.keys())[1]

        mongo_id = str(cursor['_id']).split('\'')[0]

        if not pure:
            result_users[user_id] = Traveller(user_id, user_dict['travellerName'], user_dict['travellerEmail'],
                                            user_dict['travellerPassword'])
        else:
            user_dict.update({'mongoId': mongo_id})
            result_users[user_id] = user_dict

    return result_users

def get_user(traveller_id: str, check_in_extra: bool = False) -> Traveller:
    """Finds a user by id.

    Args:
        traveller_id (str): The traveller id.
        check_in_extra (bool, optional): Also checks in extra dictionaries. Defaults to False.

    Returns:
        Traveller: The Traveller object, if the traveller is found.
    """
    traveller: Traveller = None

    if IS_LOCAL:
        if traveller_id in travellers:
            traveller = travellers[traveller_id]

    else:
        users = get_users()

        if traveller_id in users:
            traveller = users[traveller_id]

    if check_in_extra:
        if traveller_id in accounts_to_create:
            traveller = accounts_to_create[traveller_id]

    return traveller

def get_user_by_email(traveller_email: str, check_in_extra: bool = False) -> Traveller:
    """Finds a traveller account by his email.

    Args:
        traveller_email (str): The traveller email.
        check_in_extra (bool, optional): Also checks in extra dictionaries. Defaults to False.

    Returns:
        Traveller: The Traveller object, if the traveller is found.
    """
    traveller: Traveller = None

    if IS_LOCAL:
        for key, item in travellers.items():
            if item.traveller_email == traveller_email:
                traveller = get_user(key)
    else:
        for key, item in get_users().items():
            if item.traveller_email == traveller_email:
                traveller = get_user(key)

    if check_in_extra:
        for key, item in accounts_to_create.items():
            if item.traveller_email == traveller_email:
                traveller = get_user(key, True)

    return traveller

def update_user(user_id: int, **kwargs) -> Traveller:
    """Updates a user's db keys, according to what is passed. If the key doesn't exist, it is created otherwise it's updated. """
    users = get_users(True)

    if not user_id in users:
        log.error('User id passed to update_user not found, aborting operation')
        return

    traveller = users[user_id]

    update_dict: Dict[str, str] = {'$set': {user_id: {}}}

    for key, value in kwargs.items():
        update_dict['$set'][user_id][key] = value

    for key, value in traveller.items():
        if key not in kwargs.keys() and key != 'mongoId':
            update_dict['$set'][user_id][key] = value

    result = mdb.users.find_one_and_update({'_id': ObjectId(traveller['mongoId'])}, update_dict)

    if result is None:
        log.error('update_user failed.')

    return get_user(user_id)

async def send_email(to: str, title: str, content: List[str]) -> None:
    """Sends an email, asynchronously.

    Args:
        to (str): The recipient of the email.
        title (str): The title of the email.
        content (List[str]): The content of the email. 1: Body, 2: Custom html, 3: An image.
    """    
    to_error = utils.check_email(to)

    if to_error:
        utils.log_error('Invalid email provided to send_email, aborting operation.', str(to_error))
        return

    email_smtp.send(to, title, content)

def is_user_logged_in(traveller_id: str):
    """Checks if someone is currently logged into a traveller account.

    Args:
        traveller_id (str): The account's id.

    Returns:
        bool: Whether or not someone is currently linked to the account.
    """    
    return traveller_id in wss_accounts.values()

""" Decorators and checks. """

def task(task: Callable):
    """Decorator. Marks a function as a task.
    
    Args:
        task (Callable): The task to mark.
    """
    
    def wrapper(task: Callable):

        name = task.__name__

        if name in tasks_list:
            log.warn(wrapper_alr_exists.format('task', name))

        tasks_list[name] = task

    return wrapper(task)

def account(event: Callable):
    """Decorator. Marks an event as only accessible with an account. Overwrites duplicates.

    Args:
        event (Callable): The event to mark.
    """

    def wrapper(event: Callable):

        name = event.__name__

        """ Don't mind if it overwrites another one, just warn. """
        if name in account_events:
            log.warn(wrapper_alr_exists.format('account only event', name))

        account_events[name] = event

    return wrapper(event)

def account_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """ account_only decorator check. """
    if not has_account(wss.remote_address[0]):
        return format_res_err(event, 'AccountOnly', 'You must login to an account first before using this event.', True)

def no_account(event: Callable):
    """Decorator. Marks an event as only accessible without an account. Overwrites duplicates.

    Args:
        event (Callable): The event to mark.
    """

    def wrapper(event: Callable):

        name = event.__name__

        if name in no_account_events:
            log.warn(wrapper_alr_exists.format('no account only event', name))

        no_account_events[name] = event

    return wrapper(event)

def no_account_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """ no_account_only decorator check. """
    if has_account(wss.remote_address[0]):
        return format_res_err(event, 'NoAccountOnly', 'You must logout of your current account first before using this event.', True)

""" Events """

""" NO ACCOUNT ONLY """

@no_account
def create_traveller(event: str, traveller_name: str, traveller_email: str, traveller_password: str):
    """Schedules an account for creation, after it's verified with verifyTraveller.

    Possible Responses:
        createTravellerReply: The websocket has successfully created a traveller. verifyTraveller must now be called with the sent code.

        createTravellerNameExceedsLimit: The provided name exceeds the current name length limitations.
        createTravellerNameInvalidCharacters: The name of the account contains invalid characters.

        createTravellerEmailExceedsLimit: The provided name exceeds the current email length limitations.
        createTravellerEmailInvalidCharacters: The email of the account contains invalid characters.
        createTravellerEmailInvalidFormat: The provided email is not formatted correctly. Possibly the domain name is omitted/invalid.
        createTravellerEmailInUse: The provided email is already in use.

        createTravellerPasswordExceedsLimit: The provided password exceeds the current password length limitations.
    """

    """ Username checks. """
    traveller_name = traveller_name.strip()

    if not utils.check_length(traveller_name, MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH):
        return format_res_err(event, 'NameExceedsLimit', length_invalid.format('Traveller name', MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH))

    if not utils.check_chars(traveller_name, USERNAME_CHARACTERS):
        return format_res_err(event, 'NameInvalidCharacters', chars_invalid.format('The traveller name'))

    """ Email checks. """
    traveller_email = traveller_email.strip()

    if not utils.check_length(traveller_email, MIN_EMAIL_LENGTH, MAX_EMAIL_LENGTH):
        return format_res_err(event, 'EmailExceedsLimit', length_invalid.format('Traveller email', MIN_EMAIL_LENGTH, MAX_EMAIL_LENGTH))
    
    if not utils.check_chars(traveller_email, EMAIL_CHARACTERS):
        return format_res_err(event, 'EmailInvalidCharacters', chars_invalid.format('The traveller email'))

    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, 'EmailInvalidFormat', str(traveller_email_error))

    if get_user_by_email(traveller_email, True):
        return format_res_err(event, 'EmailInUse', 'This email is already in use by another account.')

    """ Password checks. """
    traveller_password = utils.format_password(traveller_password)

    traveller_password_checks = utils.check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    """ Finally, create the account. """
    traveller_id = utils.gen_id()

    """ rounds=13 so as to exceed the 214ms bare limit according to: https://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256. """
    hashed_password = hashpw(bytes(traveller_password, encoding='ascii'), gensalt(rounds=13))

    traveller_verification = ''

    if not IS_TEST:
        traveller_verification = utils.gen_verification_code()
        loop.create_task(send_email(traveller_email, email_title.format('email verification code'), [f"{email_content_code.format('email verification')}{traveller_verification}"]))
    else:
        traveller_verification = '123456'

    accounts_to_create[traveller_email] = TempTraveller(traveller_id, traveller_name, traveller_email, hashed_password, traveller_verification)

    return format_res(event, travellerId=traveller_id)

@no_account
def login_traveller(event: str, traveller_email: str, traveller_password: str, wss: WebSocketServerProtocol):
    """Links an IP to a traveller account.

    Possible Responses:
        loginTravellerReply: The IP has been successfully linked to a traveller account.

        loginTravellerEmailExceedsLimit: The provided email exceeds the current name length limitations.
        loginTravellerEmailInvalidCharacters: The email of the account contains invalid characters.
        loginTravellerEmailInvalidFormat: The provided email is not formatted correctly. Possibly the domain name is omitted/invalid.

        loginTravellerPasswordExceedsLimit: The provided password exceeds current password length limitations.

        loginTravellerNotFound: The traveller with the requested ID could not be found.
        loginTravellerAccountTaken: The target account is already taken by another IP.
        loginTravellerInvalidPassword: The given password doesn't match the original one.
    """

    """ Email checks. """
    traveller_email = traveller_email.strip()

    if not utils.check_length(traveller_email, MIN_EMAIL_LENGTH, MAX_EMAIL_LENGTH):
        return format_res_err(event, 'EmailExceedsLimit', length_invalid.format('Traveller email', MIN_EMAIL_LENGTH, MAX_EMAIL_LENGTH))

    if not utils.check_chars(traveller_email, EMAIL_CHARACTERS):
        return format_res_err(event, 'EmailInvalidCharacters', chars_invalid.format('The traveller email'))

    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, 'EmailInvalidFormat', str(traveller_email_error))
    
    traveller = get_user_by_email(traveller_email)

    if not traveller:
        return format_res_err(event, 'NotFound', f'The Traveller with email {traveller_email} could not be found.')

    """ Password checks. """
    traveller_password = utils.format_password(traveller_password)

    traveller_password_checks = utils.check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    """ Finally, login the IP to the account. """
    if checkpw(bytes(traveller_password, encoding='ascii'), travellers[traveller.traveller_id].traveller_password if IS_LOCAL
                                                            else get_users()[traveller.traveller_id].traveller_password):
        if is_user_logged_in(traveller.traveller_id):
            return format_res_err(event, 'AccountTaken', 'Another user has already logged into this account.')
    
        wss_accounts[wss.remote_address[0]] = traveller.traveller_id

        return format_res(event, travellerId=traveller.traveller_id)

    return format_res_err(event, 'InvalidPassword', f'The password is invalid.')

@no_account
def verify_traveller(event: str, traveller_email: str, traveller_code: str, wss: WebSocketServerProtocol):
    """Verifies a traveller account if its present and the code is correct.

    Possible Responses:
        verifyTravellerReply: The email of the traveller has been successfully verified.
        
        verifyTravellerNotFound: The specified traveller could not be found.
        verifyTravellerCodeExceedsLimit: The code's length is not VERIFICATION_CODE_LENGTH.
        verifyTravellerInvalidCode: The verification code is invalid.
    """
    
    if traveller_email not in accounts_to_create:
        return format_res_err(event, 'NotFound', f'The Traveller with email {traveller_email} could not be found.')

    if len(traveller_code) == VERIFICATION_CODE_LENGTH:
        if accounts_to_create[traveller_email].traveller_code == traveller_code:
            
            target_acc = accounts_to_create[traveller_email]
            
            if IS_LOCAL:
                travellers[target_acc.traveller_id] = Traveller(target_acc.traveller_id, target_acc.traveller_name, target_acc.traveller_email, target_acc.traveller_password)
            else:
                mdb.users.insert_one({target_acc.traveller_id: {'travellerName': target_acc.traveller_name, 'travellerEmail': target_acc.traveller_email,
                                                                'travellerPassword': target_acc.traveller_password}})
            
            wss_accounts[wss.remote_address[0]] = target_acc.traveller_id
            
            del accounts_to_create[target_acc.traveller_email]
            
            return format_res(event, travellerId=target_acc.traveller_id)
        else:
            return format_res_err(event, 'InvalidCode', 'The provided code is invalid.')
    else:
        return format_res_err(event, 'CodeExceedsLimit', f'The verification code must consist of exactly {VERIFICATION_CODE_LENGTH} characters.')

""" ACCOUNT ONLY"""

@account
def logout_traveller(event: str, wss: WebSocketClientProtocol):
    """Unlinks an IP from its associated traveller account. 

    Possible Responses:
        logoutTravellerReply: The IP has been successfully unliked from its associated account.
    """
    del wss_accounts[wss.remote_address[0]]

    return format_res(event)

@account
def fetch_travellers(event: str):
    """Fetches every single traveller's ID.
        
    Possible Responses:
        fetchTravellersReply: The existing travellers' IDs have been successfully fetched.
    """
    return format_res(event, travellerIds=[id for id in travellers] if IS_LOCAL else [id for id in get_users()])

@account
def fetch_traveller(event: str, traveller_id: str):
    """Fetches a traveller's info, if he exists in the database.

    Possible Responses:
        fetchTravellerReply: Info about a traveller has been successfully fetched.

        fetchTravellerNotFound: The traveller with the requested ID could not be found.
    """
    traveller = get_user(traveller_id)

    if traveller:
        return format_res(event, travellerName=traveller.traveller_name, travellerId=traveller_id)

    return format_res_err(event, 'NotFound', f'Traveller with id {traveller_id} not found.')

@account
def total_travellers(event: str):
    """Returns the number of created (only the verified ones) traveller accounts.
        
    Possible Responses:
        totalTravellersReply: The number of existing travellers has been successfully fetched.
    """
    return format_res(event, totalTravellers=len(travellers) if IS_LOCAL else len(get_users()))

@account
def online_travellers(event: str):
    """Returns the number of online (logged in) travellers.
    
    Possible Responses:
        onlineTravellersReply: The number of online travellers at the moment.
    """
    return format_res(event, onlineTravellers=len(wss_accounts))

""" Main """

async def request_switcher(wss: WebSocketClientProtocol, data: dict):
    """Calls events, dynamically.

    Possible Responses:
        EventEmpty: The event key is empty.
        EventNotFound: The given event could not be found.
        FormatError: The format of the request is incorrect.
        EventUnknownError: There was an error processing the event.

        Decorator Check Responses:
            AccountOnly: The requested event requires that this IP be associated with an account.
            NoAccountOnly: The requested event requires that this IP NOT be associated with an account.
    """

    try:
        event = data['event']
        assert len(data['event']) > 0
    except (KeyError, AssertionError):
        return format_res_err('', 'EventEmpty', 'The event key is empty/isn\'t provided.', True, True)

    transformed_event = utils.transform_to_call(event)

    target_function: function = None
    
    """ Run decorators and their respective checks. """
    for decorator in decorators_list:

        decorator_events = dict(globals())[f'{decorator}_events']
        
        if transformed_event in decorator_events:

            decorator_check_func = dict(globals())[f'{decorator}_check']

            decorator_check_args = {'event': event}

            if 'wss' in getfullargspec(decorator_check_func).args:
                decorator_check_args['wss'] = wss

            decorator_check_result = decorator_check_func(**decorator_check_args)

            if decorator_check_result:
                return decorator_check_result

            target_function = decorator_events[transformed_event]

    if not target_function:
        return format_res_err(event, 'EventNotFound', 'This event doesn\'t exist.', True)

    target_arg_names = getfullargspec(target_function).args

    target_args = {}

    for arg, value in data.items():
        if utils.transform_to_call(arg) in target_arg_names:
            arg_to_add = utils.transform_to_call(arg)
                
            if arg == 'event':
                arg_to_add = arg

            target_args[arg_to_add] = value

    if 'wss' in target_arg_names:
        target_args['wss'] = wss

    args_errored = utils.check_loop_data(target_args, target_arg_names)

    if args_errored:
        return format_res_err(event, 'FormatError', args_errored, True)

    try:
        return target_function(**target_args)

    except Exception as e:

        if IS_LOCAL or IS_TEST:
            utils.log_error(f'Error occured while calling {event}', e)
        else:
            try:
                mdb.logs.insert_one({f'bug-{str(uuid4())}': {'error': f'{e.__class__.__name__}: {e}', 'date': strftime(strf_format, gmtime())}})
                log.info('A bug report has been created, check the database\'s logs collection.')
            except:
                utils.log_error_and_exit('Fatal database error', e)

        return format_res_err(event, 'EventUnknownError', 'Unknown internal server error.', True)

async def serve(wss: WebSocketClientProtocol, path: str) -> None:
    """Called only by websockets.serve.

    Possible Responses:
        RatelimitError: The IP has reached the max requests allowed at a specified time length.
        JSONFormatError: The request contains invalid JSON.
    """

    global wss_accounts

    log.info(f'A traveller has connected. Travellers online: {len(wss_accounts)}')

    if wss.remote_address[0] not in ip_requests:
        ip_requests[wss.remote_address[0]] = 0

    while True:
        try:
            response = await wss.recv()

            result = ''

            try:
                if ip_requests[wss.remote_address[0]] > IP_RATELIMIT_MAX:

                    await wss.send(format_res_err('', 'RatelimitError', 'You are ratelimited.', True, True))
                    continue

            except KeyError:
                ip_requests[wss.remote_address[0]] = 0

            ip_requests[wss.remote_address[0]] += 1

            if len(response.strip()) == 0:
                continue

            try:
                data = loads(response)

                assert isinstance(data, dict)
                
                for key, item in data.items():
                    assert isinstance(key, str)
                    assert isinstance(item, str)

            except (JSONDecodeError, AssertionError):
                result = format_res_err('', 'JSONFormatError', 'The request contains invalid JSON.', True, True)

            if result:
                await wss.send(result)
                continue

            global current_ref

            if 'ref' in data:
                current_ref = data['ref']

            if not result:
                result = await request_switcher(wss, data)

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
            if has_account(wss.remote_address[0]) and not IS_TEST:
                del wss_accounts[wss.remote_address[0]]

            log.info(f'A traveller has disconnected. Code: {e.code} | Travellers online: {len(wss_accounts)}')

            break

def setup_mongo(mongodb_username: str, mongodb_password: str) -> None:
    """Sets up MongoDB for production servers.

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

        """ Prevent cold-booting MongoDB requests. """
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
    email_address_error = utils.check_email(email_address)

    if email_address_error:
        utils.log_error_and_exit('Invalid email provided for setup_email', str(email_address_error))

    global email_smtp
    email_smtp = SMTP(email_address, email_password)
    
    log.info('Successfully setup email account.')

""" Tasks """

@task
async def cleanup_ip_ratelimits() -> None:
    """ SETS every key found in the ip_requests dictionary to 0. """

    while True:
        for ip in ip_requests:
            ip_requests[ip] = 0

        await asyncio.sleep(IP_RATELIMIT_CLEANUP_INTERVAL)

@task
async def cleanup_ip_requests() -> None:
    """ CLEARS every key found in the ip_requests dictionary. """

    while True:
        ip_requests.clear()
        await asyncio.sleep(IP_REQUESTS_CLEANUP_INTERVAL)

@task
async def cleanup_account_links() -> None:
    """ CLEARS the linked IPs and accounts dictionary. """

    while True:
        wss_accounts.clear()
        await asyncio.sleep(IP_ACCOUNT_CLEANUP_INTERVAL)

@task
async def cleanup_temp_accounts() -> None:
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

    port = environ.get('PORT', 5000)

    start_server = ws_serve(serve, '0.0.0.0', port)

    for task in tasks_list.values():
        loop.create_task(task())

    if len(tasks_list) > 0:
        log.info('Tasks started.')

    try:
        loop.run_until_complete(start_server)
    except Exception as e:
        utils.log_error_and_exit('Server failed to start', e)

    try:
        log.info(f'Server running at: {gethostbyname(gethostname())}:{port}')
    except gaierror:
        log.info(f'Server running at port: {port}')

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        utils.log_error_and_exit('Server shut down due to an error', e)
