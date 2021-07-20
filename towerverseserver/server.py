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

""" Command-line options. """
from argparse import ArgumentParser

""" Setup optional command-line arguments. """
parser = ArgumentParser(description='The main file of the server of TowerVerse.')

parser.add_argument('--local', help='This option should be passed whenever the server is developed locally. With this option, the server makes use of runtime variables rather than MongoDB. Small reminder that this option still requires that email environmental variables be set.', action='store_true')
parser.add_argument('--test', help='This option disables removing IP account links between disconnects to facilitate pytest. Most of the time, it shouldn\'t be used for anything else. This option must be used with --local.', action='store_true')
parser.add_argument('--log', help='Specifies the level of logging where: 10 Verbose 20 Info 30 Warning 40 Error 50 Silent. Defaults to 10.', type=int, default=10, choices=[10, 20, 30, 40, 50])

parser_args = parser.parse_args()

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
if not parser_args.test:
    from bson.objectid import ObjectId
    from pymongo import MongoClient
    from pymongo.database import Database
    from pymongo.errors import ConfigurationError, OperationFailure

""" Email verification and more. """
if not parser_args.test:
    from aioyagmail import SMTP

""" LOCAL MODULES """

import towerverseserver.utils as utils
from towerverseserver.classes import *
from towerverseserver.constants import *

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

""" The created guilds. """
guilds: Dict[str, Guild] = {}

""" The created towers. """
towers: Dict[str, Tower] = {}

""" Accounts linked to IPs. """
wss_accounts: Dict[str, str] = {}

""" Accounts to create when verified. """
accounts_to_create: Dict[str, TempTraveller] = {}

""" Email change request codes to verify. """
email_change_request_codes: Dict[str, str] = {}

""" Password change request codes to verify. """
password_change_request_codes: Dict[str, str] = {}

""" Whether or not this is a locally-hosted server. """
IS_LOCAL = parser_args.local

""" Used to facilitate, do not use this for prod/testing dev. Rather, use it with pytest. """
IS_TEST = parser_args.test

""" MongoDB-related, filled in at setup_mongo. """
if not parser_args.test:
    mdbclient: MongoClient = None
    mdb: Database = None

""" Passed reference to facilitate wrapper-fetching. """
current_ref: str = None

""" Email-related, filled in at setup_email. """
if not parser_args.test:
    email_smtp: SMTP = None

""" Account-only events. These are only used if the requestee is logged in to an account, otherwise an error is thrown. Filled in with the account_only decorator. """
account_events: Dict[str, Callable] = {}

""" No-account-events. These are only used if the requestee is NOT logged in to an account, otherwise an error is thrown. Filled in with the no_account_only decorator. """
no_account_events: Dict[str, Callable] = {}

""" Guild-only. These are only used if the requestee is part of a guild otherwise an error is thrown. Filled in with the guild_only decorator. """
guild_events: Dict[str, Callable] = {}

""" No-guild-only. These are only used if the requestee is NOT part of a guild otherwise an error is thrown. Filled in with the guild_only decorator. """
no_guild_events: Dict[str, Callable] = {}

""" List of all decorators, checked by request_switcher. """
decorators_list: Set[str] = set({'account', 'no_account', 'guild', 'no_guild'})

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
        pure (bool): Whether or not Traveller objects should be returned otherwise the raw data will be.

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
                                            user_dict['travellerPassword'], user_dict['hasChangedName'], user_dict['isInGuild'],
                                            user_dict['guildId'])
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
        temp_users = get_users()

        if traveller_id in temp_users:
            traveller = temp_users[traveller_id]

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

def update_user(user_id: str, **kwargs) -> Traveller:
    """Updates a user's db keys, according to what is passed. If the key doesn't exist, it is created otherwise it's updated. 
    
    Args:
        user_id (int): The traveller's id.
    
    Returns:
        Traveller: The updated Traveller instance.
    """
    users = get_users(True)

    if not user_id in users:
        log.error('Invalid id has been passed to update_user, aborting operation')
        return

    traveller = users[user_id]

    update_dict: Dict[str, str] = {'$set': {user_id: {}}}

    for key, value in kwargs.items():
        update_dict['$set'][user_id][key] = value

    for key, value in traveller.items():
        if key not in kwargs.keys() and key != 'mongoId':
            update_dict['$set'][user_id][key] = value

    mdb.users.find_one_and_update({'_id': ObjectId(traveller['mongoId'])}, update_dict)

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

def is_username_taken(traveller_name: str) -> bool:
    """Checks if a username is taken by another account.

    Args:
        traveller_name (str): The target traveller name.

    Returns:
        bool: Whether or not it is taken.
    """

    is_name_taken = False

    if IS_LOCAL:
        is_name_taken = len([traveller for traveller in travellers.values() if traveller.traveller_name == traveller_name]) > 0

    else:
        is_name_taken = len([traveller for traveller in get_users().values() if traveller.traveller_name == traveller_name]) > 0

    if not is_name_taken:
        is_name_taken = len([traveller for traveller in accounts_to_create.values() if traveller.traveller_name == traveller_name]) > 0

    return is_name_taken

def get_guilds(pure: bool = False) -> Dict[str, Guild]:
    """Returns created guilds. Only for the database version.

    Args:
        pure (bool): Whether or not Guild objects should be returned otherwise the raw data will be.

    Returns:
        Dict[str, Guild]: The guilds dictionary.
    """
    result_guilds: Dict[str, Guild] = {}
    
    for cursor in mdb.guilds.find({}):
        guild_dict = list(cursor.values())[1]
        guild_id = list(cursor.keys())[1]

        mongo_id = str(cursor['_id']).split('\'')[0]

        if not pure:
            result_guilds[guild_id] = Guild(guild_id, guild_dict['guildName'], guild_dict['guildCreator'], 
                                        guild_dict['guildVisibility'], guild_dict['guildMaxMembers'], guild_dict['guildMembers'])
            
        else:
            guild_dict.update({'mongoId': mongo_id})
            result_guilds[guild_id] = guild_dict

    return result_guilds

def get_guild(guild_id: str) -> Guild:
    """Gets a guild by id.

    Args:
        guild_id (str): The guild id.
        
    Returns:
        Guild: The Guild object, if the guild is found.
    """    
    guild: Guild = None

    if IS_LOCAL:
        if guild_id in guilds:
            guild = guilds[guild_id]
            
    else:
        temp_guilds = get_guilds()

        if guild_id in temp_guilds:
            guild = temp_guilds[guild_id]
            
    return guild

def update_guild(guild_id: str, **kwargs) -> Guild:
    """Updates a guild's db keys, according to what is passed. If the key doesn't exist, it is created otherwise it's updated. 
    
    Args:
        guild_id (int): The guild's id.
    
    Returns:
        Guild: The updated Guild instance.
    """
    guilds = get_guilds(True)

    if not guild_id in guilds:
        log.error('Invalid id has been passed to update_guild, aborting operation.')
        return

    guild = guilds[guild_id]

    update_dict: Dict[str, str] = {'$set': {guild_id: {}}}

    for key, value in kwargs.items():
        update_dict['$set'][guild_id][key] = value

    for key, value in guild.items():
        if key not in kwargs.keys() and key != 'mongoId':
            update_dict['$set'][guild_id][key] = value

    mdb.guilds.find_one_and_update({'_id': ObjectId(guild['mongoId'])}, update_dict)

    return get_user(guild_id)

def get_guild_info(guild_id: str, event: str = '') -> dict:
    """Returns guild info as a response, if the event argument is provided, otherwise as a plain dict.

    Args:
        guild_id (str): The guild id.
        event (str, optional): The given event. Defaults to ''.

    Returns:
        dict: Response, if the event is provided, or a plain dict.
    """    
    guild = get_guild(guild_id)
    
    result_dict = dict(guildId=guild.guild_id, guildName=guild.guild_name,
                        guildCreator=guild.guild_creator, guildVisibility=guild.guild_visibility,
                        guildMaxMembers=guild.guild_max_members, guildMembers=guild.guild_members)
    
    if event:
        return format_res(event, **result_dict)

    return result_dict

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
            GuildOnly: The requested event requires that this account is part of a guild.
            NoGuildOnly: The requested event requires that this account is NOT part of a guild.
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

    if 'account' in target_arg_names:
        target_args['account'] = get_user(wss_accounts[wss.remote_address[0]])

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

            try:
                if ip_requests[wss.remote_address[0]] > IP_RATELIMIT_MAX:

                    await wss.send(format_res_err(data['event'], 'RatelimitError', 'You are ratelimited.', True))
                    continue

            except KeyError:
                ip_requests[wss.remote_address[0]] = 0

            if not IS_TEST:
                ip_requests[wss.remote_address[0]] += 1
                
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
        log.error('The TowerVerse database may be temporarily down or there\'s no internet connection, exiting.')
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
        
        return event

    return wrapper(event)

def account_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """ account decorator check. """
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
        
        return event

    return wrapper(event)

def no_account_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """ no_account decorator check. """
    if has_account(wss.remote_address[0]):
        return format_res_err(event, 'NoAccountOnly', 'You must logout of your current account first before using this event.', True)

def guild(event: Callable):
    """Decorator. Marks an event as only accessible within a guild. Overwrites duplicates.

    Args:
        event (Callable): The event to mark.
    """

    def wrapper(event: Callable):

        name = event.__name__

        if name in guild_events:
            log.warn(wrapper_alr_exists.format('guild only event', name))

        guild_events[name] = event
        
        return event

    return wrapper(event)

def guild_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """ guild decorator check. """
    target_user = get_user(wss_accounts[wss.remote_address[0]])
    
    if not target_user:
        return
    
    if not target_user.is_in_guild:
        return format_res_err(event, 'GuildOnly', 'You must be part of a guild before using this event.', True)

def no_guild(event: Callable):
    """Decorator. Marks an event as only accessible while NOT within a guild. Overwrites duplicates.

    Args:
        event (Callable): The event to mark.
    """

    def wrapper(event: Callable, *args, **kwargs):

        name = event.__name__

        if name in no_guild_events:
            log.warn(wrapper_alr_exists.format('no guild only event', name))

        no_guild_events[name] = event
        
        return event

    return wrapper(event)

def no_guild_check(event: str, wss: WebSocketClientProtocol) -> bool:
    """ no_guild decorator check. """
    target_user = get_user(wss_accounts[wss.remote_address[0]])
    
    if not target_user:
        return
    
    if target_user.is_in_guild:
        return format_res_err(event, 'NoGuildOnly', 'You must leave your current guild before using this event.', True)

""" Events """

""" No account only """

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
        createTravellerPasswordInvalidCharacters: The password of the account contains invalid characters.
    """

    """ Username checks. """
    traveller_name = traveller_name.strip()

    if not utils.check_length(traveller_name, MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH):
        return format_res_err(event, 'NameExceedsLimit', length_invalid.format('Traveller name', MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH))

    if not utils.check_chars(traveller_name, USERNAME_CHARACTERS):
        return format_res_err(event, 'NameInvalidCharacters', chars_invalid.format('The traveller name'))

    """ Email checks. """
    traveller_email = traveller_email.strip()

    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, traveller_email_error[0], traveller_email_error[1])

    if get_user_by_email(traveller_email, True):
        return format_res_err(event, 'EmailInUse', 'This email is already in use by another account.')

    """ Password checks. """
    traveller_password = utils.remove_whitespace(traveller_password)

    traveller_password_checks = utils.check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    """ Create the account. """
    traveller_id = utils.gen_id() if not IS_TEST else '123'

    """ rounds=13 so as to exceed the 214ms bare limit according to: https://security.stackexchange.com/questions/3959/recommended-of-iterations-when-using-pkbdf2-sha256. """
    hashed_password = hashpw(bytes(traveller_password, encoding='ascii'), gensalt(rounds=13))

    traveller_verification = ''

    if not IS_TEST:
        traveller_verification = utils.gen_verification_code()
        loop.create_task(send_email(traveller_email, email_title.format('email verification code'), [f"{email_content_code.format('email verification')}{traveller_verification}"]))
    else:
        traveller_verification = '123456'

    accounts_to_create[traveller_email] = TempTraveller(traveller_id, traveller_name, traveller_email,
                                                        hashed_password, False, False, '', traveller_verification)

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
        loginTravellerPasswordInvalidCharacters: The password of the account contains invalid characters.

        loginTravellerNotFound: The traveller with the requested ID could not be found.
        loginTravellerAccountTaken: The target account is already taken by another IP.
        loginTravellerInvalidPassword: The given password doesn't match the original one.
    """

    """ Email checks. """
    traveller_email = traveller_email.strip()

    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, traveller_email_error[0], traveller_email_error[1])
    
    traveller = get_user_by_email(traveller_email)

    if not traveller:
        return format_res_err(event, 'NotFound', f'The Traveller with email {traveller_email} could not be found.')

    """ Password checks. """
    traveller_password = utils.remove_whitespace(traveller_password)

    traveller_password_checks = utils.check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    if not checkpw(bytes(traveller_password, encoding='ascii'), travellers[traveller.traveller_id].traveller_password if IS_LOCAL
                                                            else get_users()[traveller.traveller_id].traveller_password):
        return format_res_err(event, 'InvalidPassword', 'The password is invalid.')

    """ Login to the account. """
    if is_user_logged_in(traveller.traveller_id):
        return format_res_err(event, 'AccountTaken', 'Another user has already logged into this account.')

    wss_accounts[wss.remote_address[0]] = traveller.traveller_id

    return format_res(event, travellerId=traveller.traveller_id)

@no_account
def verify_traveller(event: str, traveller_email: str, traveller_code: str, wss: WebSocketServerProtocol):
    """Verifies a traveller account if its present and the code is correct.

    Possible Responses:
        verifyTravellerReply: The email of the traveller has been successfully verified.
        
        verifyTravellerEmailExceedsLimit: The provided email exceeds the current name length limitations.
        verifyTravellerEmailInvalidCharacters: The email of the account contains invalid characters.
        verifyTravellerEmailInvalidFormat: The provided email is not formatted correctly. Possibly the domain name is omitted/invalid.

        verifyTravellerNotFound: The specified traveller could not be found.
        verifyTravellerCodeExceedsLimit: The code's length is not VERIFICATION_CODE_LENGTH.
        verifyTravellerInvalidCode: The verification code is invalid.
    """
    
    """ Email checks. """
    traveller_email = traveller_email.strip()

    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, traveller_email_error[0], traveller_email_error[1])

    if traveller_email not in accounts_to_create:
        return format_res_err(event, 'NotFound', f'The Traveller with email {traveller_email} could not be found.')

    """ Verify the account. """
    if not len(traveller_code) == VERIFICATION_CODE_LENGTH:
        return format_res_err(event, 'CodeExceedsLimit', f'The verification code must consist of exactly {VERIFICATION_CODE_LENGTH} characters.')

    if not accounts_to_create[traveller_email].traveller_code == traveller_code:
        return format_res_err(event, 'InvalidCode', 'The provided code is invalid.')
        
    target_acc = accounts_to_create[traveller_email]
    
    if IS_LOCAL:
        travellers[target_acc.traveller_id] = Traveller(target_acc.traveller_id, target_acc.traveller_name, target_acc.traveller_email,
                                                        target_acc.traveller_password, target_acc.has_changed_name, target_acc.is_in_guild,
                                                        target_acc.guild_id)
    else:
        mdb.users.insert_one({target_acc.traveller_id: {'travellerName': target_acc.traveller_name, 'travellerEmail': target_acc.traveller_email,
                                                        'travellerPassword': target_acc.traveller_password, 'hasChangedName': target_acc.has_changed_name,
                                                        'isInGuild': target_acc.is_in_guild, 'guildId': target_acc.guild_id}})
    
    wss_accounts[wss.remote_address[0]] = target_acc.traveller_id
    
    del accounts_to_create[target_acc.traveller_email]
    
    if not IS_TEST:
        loop.create_task(send_email(target_acc.traveller_email, email_title.format('account created successfully'),
                                    [f'Your TowerVerse account has been successfully created with the following credentials:\n\nUsername: {target_acc.traveller_name}\n\nWe hope that you have a great time gaming!']))

    return format_res(event, travellerId=target_acc.traveller_id)

@no_account
def resend_traveller_code(event: str, traveller_email: str):
    """Re-sends a traveller's verification code.

    Possible Responses:
        resendTravellerCodeReply: The code has been re-sent successfully.

        resendTravellerCodeEmailExceedsLimit: The provided email exceeds the current name length limitations.
        resendTravellerCodeEmailInvalidCharacters: The email of the account contains invalid characters.
        resendTravellerCodeEmailInvalidFormat: The provided email is not formatted correctly. Possibly the domain name is omitted/invalid.

        resendTravellerCodeNotFound: The specified traveller could not be found.
    """    

    """ Email checks. """
    traveller_email = traveller_email.strip()

    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, traveller_email_error[0], traveller_email_error[1])

    """ Send traveller verification code. """
    target_acc = get_user_by_email(traveller_email, True)

    if not target_acc or not isinstance(target_acc, TempTraveller):
        return format_res_err(event, 'NotFound', f'Traveller with email {traveller_email} could not be found.')

    if not IS_TEST:
        loop.create_task(send_email(traveller_email, email_title.format('email verification code'), [f"{email_content_code.format('email verification')}{target_acc.traveller_code}"]))
    
    return format_res(event)

@no_account
def reset_traveller_password(event: str, traveller_email: str, old_traveller_password: str, new_traveller_password: str):
    """Resets a not-connected traveller's password.

    Possible Responses:
        resetTravellerPasswordReply: A password change request code has been sent to the new email, call resetTravellerPasswordFinal now.

        resetTravellerPasswordEmailExceedsLimit: The provided email exceeds the current name length limitations.
        resetTravellerPasswordEmailInvalidCharacters: The email of the account contains invalid characters.
        resetTravellerPasswordEmailInvalidFormat: The provided email is not formatted correctly. Possibly the domain name is omitted/invalid.

        resetTravellerPasswordPasswordExceedsLimit: The provided password exceeds current password length limitations.
        resetTravellerPasswordPasswordInvalidCharacters: The password of the account contains invalid characters.

        resetTravellerPasswordInvalidPassword: The given password doesn't match the original one.
    """

    """ Email checks. """
    traveller_email = traveller_email.strip()

    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, traveller_email_error[0], traveller_email_error[1])

    """ Password checks. """
    old_traveller_password, new_traveller_password = utils.remove_whitespace(old_traveller_password), utils.remove_whitespace(new_traveller_password)

    old_traveller_password_checks, new_traveller_password_checks = utils.check_password(old_traveller_password), utils.check_password(new_traveller_password)

    if old_traveller_password_checks:
        return format_res_err(event, old_traveller_password_checks[0], old_traveller_password_checks[1])
        
    if new_traveller_password_checks:
        return format_res_err(event, new_traveller_password_checks[0], new_traveller_password_checks[1])

    target_acc = get_user_by_email(traveller_email)

    if not target_acc:
        return format_res_err(event, 'NotFound', f'The Traveller with email {traveller_email} could not be found.')

    if not checkpw(bytes(old_traveller_password, 'ascii'), target_acc.traveller_password):
        return format_res_err(event, 'InvalidPassword', 'The password is invalid.')

    """ Reset password and send email. """

    traveller_verification = utils.gen_verification_code() if not IS_TEST else '123456'

    if not IS_TEST:
        traveller_verification = utils.gen_verification_code()
        loop.create_task(send_email(traveller_email, email_title.format('password change request code'),
                                    [f"{email_content_code.format('password change request')}{traveller_verification}"]))

    else:
        traveller_verification = '123456'

    password_change_request_codes[target_acc.traveller_id] = [traveller_verification, new_traveller_password]

    return format_res(event)

@no_account
def reset_traveller_password_final(event: str, traveller_email: str, traveller_password_code: str):
    """Called after resetTravellerPassword to perform the actual operation with the given code.

    Possible Responses:
        resetTravellerPasswordFinalReply: The traveller's password has been successfully reset.
        
        resetTravellerPasswordFinalEmailExceedsLimit: The provided email exceeds the current name length limitations.
        resetTravellerPasswordFinalEmailInvalidCharacters: The email of the account contains invalid characters.
        resetTravellerPasswordFInalEmailInvalidFormat: The provided email is not formatted correctly. Possibly the domain name is omitted/invalid.
        
        resetTravellerPasswordFinalNoCode: You haven't called resetTravellerPassword.
        resetTravellerPasswordFinalCodeExceedsLimit: The code's length is not VERIFICATION_CODE_LENGTH.
        resetTravellerPasswordFinalInvalidCode: The verification code is invalid.
    """    
    
    """ Email checks. """
    traveller_email_error = utils.check_email(traveller_email)

    if traveller_email_error:
        return format_res_err(event, traveller_email_error[0], traveller_email_error[1])

    """ Reset password and send email. """
    if not len(traveller_password_code) == VERIFICATION_CODE_LENGTH:
        return format_res_err(event, 'CodeExceedsLimit', f'The verification code must consist of exactly {VERIFICATION_CODE_LENGTH} characters.')

    target_acc = get_user_by_email(traveller_email)

    if not target_acc:
        return format_res_err(event, 'NotFound', f'The Traveller with email {traveller_email} could not be found.')

    if not target_acc.traveller_id in password_change_request_codes:
        return format_res_err(event, 'NoCode', 'No password change code has been requested.')

    if not password_change_request_codes[target_acc.traveller_id][0] == traveller_password_code:
        return format_res_err(event, 'InvalidCode', 'The provided code is invalid.')

    new_hashed_password = hashpw(bytes(password_change_request_codes[target_acc.traveller_id][1], 'ascii'), gensalt(rounds=13))

    if IS_LOCAL:
        travellers[target_acc.traveller_id].traveller_password = new_hashed_password
    else:
        update_user(target_acc.traveller_id, travellerPassword=new_hashed_password)

    if not IS_TEST:
        loop.create_task(send_email(target_acc.traveller_email, email_title.format('password changed'), [email_content_changed.format('password')]))

    del password_change_request_codes[target_acc.traveller_id]

    return format_res(event)

""" Account only """

@account
def logout_traveller(event: str, wss: WebSocketClientProtocol):
    """Unlinks an IP from its associated traveller account. 

    Possible Responses:
        logoutTravellerReply: The IP has been successfully unliked from its associated account.
    """
    del wss_accounts[wss.remote_address[0]]

    return format_res(event)

@account
def fetch_traveller(event: str, traveller_id: str):
    """Fetches a traveller's info, if he exists.

    Possible Responses:
        fetchTravellerReply: Info about the traveller has been successfully fetched.

        fetchTravellerNotFound: The traveller with the requested ID could not be found.
    """
    traveller = get_user(traveller_id)

    if not traveller:
        return format_res_err(event, 'NotFound', f'Traveller with id {traveller_id} not found.')
    
    return format_res(event, travellerId=traveller_id, travellerName=traveller.traveller_name,
                            isInGuild=traveller.is_in_guild, guildId=traveller.guild_id)

@account
def fetch_travellers(event: str):
    """Fetches every single traveller's ID.
        
    Possible Responses:
        fetchTravellersReply: The existing travellers' IDs have been successfully fetched.
    """
    return format_res(event, travellerIds=[id for id in travellers] if IS_LOCAL else [id for id in get_users()])

@account
def total_travellers(event: str):
    """Returns the number of created (only the verified ones) traveller accounts.
        
    Possible Responses:
        totalTravellersReply: The number of existing travellers has been successfully fetched.
    """
    return format_res(event, totalTravellers=len(travellers) if IS_LOCAL else len(get_users()))

@account
def online_travellers(event: str):
    """Returns the number of online (logged in) travellers and their IDs.
    
    Possible Responses:
        onlineTravellersReply: The number of online travellers at the moment, with their IDs.
    """

    result_data = dict(onlineTravellers=len(wss_accounts))

    if IS_LOCAL:
        online_travellers_ids = [id for id in travellers if id in wss_accounts.values()]

    else:
        online_travellers_ids = [id for id in get_users() if id in wss_accounts.values()]

    result_data['onlineTravellersIds'] = online_travellers_ids

    return format_res(event, **result_data)

@account
def reset_traveller_password_account(event: str, old_traveller_password: str, new_traveller_password: str, account: Traveller):
    """Resets a connected traveller's password.

    Possible Responses:
        resetTravellerPasswordAccountReply: The password has been changed successfully.

        resetTravellerPasswordAccountPasswordExceedsLimit: The provided password exceeds current password length limitations.
        resetTravellerPasswordAccountPasswordInvalidCharacters: The password of the account contains invalid characters.

        resetTravellerPasswordAccountInvalidPassword: The given password doesn't match the original one.
    """

    """ Password checks. """
    old_traveller_password, new_traveller_password = utils.remove_whitespace(old_traveller_password), utils.remove_whitespace(new_traveller_password)

    old_traveller_password_checks, new_traveller_password_checks = utils.check_password(old_traveller_password), utils.check_password(new_traveller_password)

    if old_traveller_password_checks:
        return format_res_err(event, old_traveller_password_checks[0], old_traveller_password_checks[1])
        
    if new_traveller_password_checks:
        return format_res_err(event, new_traveller_password_checks[0], new_traveller_password_checks[1])

    if not checkpw(bytes(old_traveller_password, 'ascii'), account.traveller_password):
        return format_res_err(event, 'InvalidPassword', 'The password is invalid.')

    """ Reset password and send email. """
    new_hashed_password = hashpw(bytes(new_traveller_password, 'ascii'), gensalt(rounds=13))

    if IS_LOCAL:
        travellers[account.traveller_id].traveller_password = new_hashed_password
    else:
        update_user(account.traveller_id, travellerPassword=new_hashed_password)

    if not IS_TEST:
        loop.create_task(send_email(account.traveller_email, email_title.format('password changed'), [email_content_changed.format('password')]))

    return format_res(event)

@account
def reset_traveller_email(event: str, traveller_password: str, new_traveller_email: str, account: Traveller):
    """Sends an email change request code to be used by resetTravellerEmailFinal.

    Possible Responses:
        resetTravellerEmailReply: An email change request code has been sent to the new email, call resetTravellerEmailFinal now.

        resetTravellerEmailEmailExceedsLimit: The provided email exceeds the current name length limitations.
        resetTravellerEmailEmailInvalidCharacters: The email of the account contains invalid characters.
        resetTravellerEmailEmailInvalidFormat: The provided email is not formatted correctly. Possibly the domain name is omitted/invalid.
        resetTravellerEmailEmailUnchanged: The original email is the same as the new one.
        resetTravellerEmailEmailInUse: The new email is already in use.

        resetTravellerEmailInvalidPassword: The given password doesn't match the original one.
    """    

    """ Email checks. """
    new_traveller_email_error = utils.check_email(new_traveller_email)

    if new_traveller_email_error:
        return format_res_err(event, new_traveller_email_error[0], new_traveller_email_error[1])

    if account.traveller_email == new_traveller_email:
        return format_res_err(event, 'EmailUnchanged', 'The old email is the same as the new one.')

    if get_user_by_email(new_traveller_email, True):
        return format_res_err(event, 'EmailInUse', 'This email is already in use by another account.')

    """ Password checks. """
    traveller_password = utils.remove_whitespace(traveller_password)

    traveller_password_checks = utils.check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    if not checkpw(bytes(traveller_password, 'ascii'), account.traveller_password):
        return format_res_err(event, 'InvalidPassword', 'The password is invalid.')

    """ Send the email change request code. """
    traveller_verification = utils.gen_verification_code() if not IS_TEST else '123456'

    if not IS_TEST:
        traveller_verification = utils.gen_verification_code()
        loop.create_task(send_email(new_traveller_email, email_title.format('email change request code'),
                                    [f"{email_content_code.format('email change request')}{traveller_verification}"]))

    else:
        traveller_verification = '123456'

    email_change_request_codes[account.traveller_id] = [traveller_verification, new_traveller_email]

    return format_res(event)

@account
def reset_traveller_email_final(event: str, traveller_email_code: str, account: Traveller):
    """Called after resetTravellerEmail to perform the actual operation with the given code.

    Possible Responses:
        resetTravellerEmailFinalReply: The traveller's email has been successfully reset.

        resetTravellerEmailFinalNoCode: You haven't called resetTravellerEmail.
        resetTravellerEmailFinalCodeExceedsLimit: The code's length is not VERIFICATION_CODE_LENGTH.
        resetTravellerEmailFinalInvalidCode: The verification code is invalid.
    """

    """ Reset and send email. """
    if account.traveller_id not in email_change_request_codes:
        return format_res_err(event, 'NoCode', 'No email change code has been requested.')

    if not len(traveller_email_code) == VERIFICATION_CODE_LENGTH:
        return format_res_err(event, 'CodeExceedsLimit', f'The verification code must consist of exactly {VERIFICATION_CODE_LENGTH} characters.')

    if not email_change_request_codes[account.traveller_id][0] == traveller_email_code:
        return format_res_err(event, 'InvalidCode', 'The provided code is invalid.')
        
    old_traveller_email = account.traveller_email

    if IS_LOCAL:
        travellers[account.traveller_id].traveller_email = email_change_request_codes[account.traveller_id][1]
    else:
        update_user(account.traveller_id, travellerEmail=email_change_request_codes[account.traveller_id][1])

    if not IS_TEST:
        loop.create_task(send_email(old_traveller_email, email_title.format('email changed'), [email_content_changed.format('email')]))

    del email_change_request_codes[account.traveller_id]

    return format_res(event)

@account
def reset_traveller_name(event: str, traveller_password: str, new_traveller_name: str, account: Traveller):
    """Changes a traveller's name, of it's not taken.

    Possible Responses:
        resetTravellerNameReply: The traveller's name has been changed successfully.

        resetTravellerNameNameExceedsLimit: The provided name exceeds the current name length limitations.
        resetTravellerNameNameInvalidCharacters: The name of the account contains invalid characters.
        resetTravellerNameNameTaken: The new traveller's name is already used by another account.
        resetTravellerNameNameAlreadyChanged: The traveller's name has already been changed once.

        resetTravellerNamePasswordExceedsLimit: The provided password exceeds current password length limitations.
        resetTravellerNamePasswordInvalidCharacters: The password of the account contains invalid characters.

        resetTravellerNameInvalidPassword: The given password doesn't match the original one.
    """    
    
    """ Username checks. """
    new_traveller_name = new_traveller_name.strip()

    if not utils.check_length(new_traveller_name, MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH):
        return format_res_err(event, 'NameExceedsLimit', length_invalid.format('New traveller name', MIN_USERNAME_LENGTH, MAX_USERNAME_LENGTH))

    if not utils.check_chars(new_traveller_name, USERNAME_CHARACTERS):
        return format_res_err(event, 'NameInvalidCharacters', chars_invalid.format('The new traveller name'))

    """ Password checks. """
    traveller_password = utils.remove_whitespace(traveller_password)

    traveller_password_checks = utils.check_password(traveller_password)

    if traveller_password_checks:
        return format_res_err(event, traveller_password_checks[0], traveller_password_checks[1])

    if not checkpw(bytes(traveller_password, 'ascii'), account.traveller_password):
        return format_res_err(event, 'InvalidPassword', 'The password is invalid.')

    """ Reset name and send email. """
    if is_username_taken(new_traveller_name):
        return format_res_err(event, 'NameTaken', 'Another traveller is already using this username.')

    has_changed_name = False

    if IS_LOCAL:
        has_changed_name = travellers[account.traveller_id].has_changed_name

    else:
        has_changed_name = get_users(True)[account.traveller_id]['hasChangedName']

    if has_changed_name:
        return format_res_err(event, 'NameAlreadyChanged', 'The traveller\'s name has already been changed once.')

    if IS_LOCAL:
        travellers[account.traveller_id].traveller_name = new_traveller_name
        travellers[account.traveller_id].has_changed_name = True
    
    else:
        update_user(account.traveller_id, travellerName=new_traveller_name, hasChangedName=True)

    if not IS_TEST:
        loop.create_task(send_email(account.traveller_email, email_title.format('username changed'), [f"{email_content_changed.format('username')}"]))

    return format_res(event)

""" No guild only """

@account
@no_guild
def create_guild(event: str, guild_name: str, guild_visibility: bool, guild_max_members: int, account: Traveller):
    """Creates a guild.

    Possible Responses:
        createGuildReply: The guild has been successfully created.
        
        createGuildNameExceedsLimit: The provided name exceeds the current guild name length limitations.
        createGuildNameInvalidCharacters: The name of the guild contains invalid characters.
        
        createGuildVisibilityInvalid: The guild visibility parameter is formatted incorrectly.
    
        createGuildMaxMembersInvalidCharacters: The guild max members key contains invalid characters.
        createGuildMaxMembersExceedsLimit: The guild max members exceeds current length limitations.
    """
    
    """ Name checks. """
    guild_name = guild_name.strip()
    
    if not utils.check_length(guild_name, MIN_GUILD_LENGTH, MAX_GUILD_LENGTH):
        return format_res_err(event, 'NameExceedsLimit', length_invalid.format('Guild name', MIN_GUILD_LENGTH, MAX_GUILD_LENGTH))
    
    if not utils.check_chars(guild_name, GUILD_CHARACTERS):
        return format_res_err(event, 'NameInvalidCharacters', chars_invalid.format('The guild name'))

    """ Visibility checks. """
    if not guild_visibility in ['public', 'private']:
        return format_res_err(event, 'VisibilityInvalid', argument_invalid_type.format('Guild visibility', 'public or private'))
    
    """ Max member checks. """
    if not utils.check_chars(guild_max_members, digits):
        return format_res_err(event, 'MaxMembersInvalidCharacters', chars_invalid.format('The guild max members key'))
    
    if not utils.check_length(guild_max_members, 1, MAX_GUILD_MAXMEMBERS):
        return format_res_err(event, 'MaxMembersExceedsLimit', length_specific_invalid.format('The guild max members value', 1, MAX_GUILD_MAXMEMBERS))
    
    guild_id = utils.gen_id() if not IS_TEST else '123456'
    guild_creator = account.traveller_id
    guild_members = [guild_creator]
    
    if IS_LOCAL:
        guilds[guild_id] = Guild(guild_id, guild_name, guild_creator, guild_visibility, guild_max_members, guild_members)
        travellers[account.traveller_id].is_in_guild = True
        travellers[account.traveller_id].guild_id = guild_id
    else:
        mdb.guilds.insert_one({guild_id: {'guildName': guild_name, 'guildCreator': guild_creator,'guildVisibility': guild_visibility,
                                          'guildMaxMembers': guild_max_members, 'guildMembers': guild_members}})
        update_user(account.traveller_id, isInGuild=True, guildId=guild_id)

    return format_res(event, guildId=guild_id)

@account
@no_guild
def join_guild(event: str, guild_id: str, account: Traveller):
    """Joins a guild.

    Possible Responses:
        joinGuildReply: The guild has been successfully joined.
        
        joinGuildNotFound: The guild with the requested ID could not be found.
        joinGuildMaxedOut: The target guild is already at max capacity.
    """
    
    """ Guild id checks. """
    guild = get_guild(guild_id)
    
    if not guild:
        return format_res_err(event, 'NotFound', f'Guild with id {guild_id} not found.')
        
    if int(guild.guild_max_members) == len(guild.guild_members):
        return format_res_err(event, 'MaxedOut', 'This guild is already full.')

    target_id = account.traveller_id

    if IS_LOCAL:
        guilds[guild_id].guild_members.append(target_id)
        travellers[target_id].is_in_guild = True
        travellers[target_id].guild_id = guild_id
        
    else:
        guild.guild_members.append(target_id)
        update_guild(guild_id, guildMembers=guild.guild_members)
        update_user(target_id, isInGuild=True, guildId=guild_id)

    return format_res(event, guildId=guild_id)

@account
@no_guild
def fetch_guild(event: str, guild_id: str):
    """Fetches a guild's info, if it exists.

    Possible Responses:
        fetchGuildReply: Info about the guild has been successfully fetched.
        
        fetchGuildNotFound: The guild with the requested ID could not be found.
    """
    if not get_guild(guild_id):
        return format_res_err(event, 'NotFound', f'Guild with id {guild_id} not found.')

    return get_guild_info(guild_id, event)

@account
@no_guild
def fetch_guilds(event: str):
    """Fetches every single guild's ID.

    Possible Responses:
        fetchGuildsReply: The existing guilds' IDs have been successfully fetched.
    """
    guild_ids = []
    
    if IS_LOCAL:
        guild_ids = [guild.guild_id for guild in guilds.values() if guild.guild_visibility == 'public']
    
    else:
        guild_ids = [guild.guild_id for guild in get_guilds().values() if guild.guild_visibility == 'public']    
    
    return format_res(event, guildIds=guild_ids)

""" Guild only """

@account
@guild
def current_guild(event: str, account: Traveller):
    """Returns info about the user's current guild.

    Possible Responses:
        currentGuildReply: Info of the current guild has been fetched.
    """
    return get_guild_info(account.guild_id, event)

@account
@guild
def leave_guild(event: str, account: Traveller):
    """Removes the user from his current guild.

    Possible Responses:
        leaveGuildReply: The user has successfully left the guild.
    """
    
    target_id = account.traveller_id
    target_guild = get_guild(account.guild_id)
    
    if IS_LOCAL:
        if target_id == target_guild.guild_creator:
            if not IS_TEST:
                del guilds[target_guild.guild_id]
            
        else:
            guilds[account.guild_id].guild_members.remove(target_id)

        travellers[target_id].is_in_guild = False
        travellers[target_id].guild_id = ''
        
    else:
        if target_id == target_guild.guild_creator:
            mdb.guilds.find_one_and_delete({'_id': ObjectId(get_guilds(True)[account.guild_id]['mongoId'])})
            
        else:
            target_guild.guild_members.remove(target_id)
        
            update_guild(account.guild_id, guildMembers=target_guild.guild_members)
        
        update_user(target_id, isInGuild=False, guildId='')
        
    return format_res(event)

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
