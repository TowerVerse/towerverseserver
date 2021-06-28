""" 
License: GPL-3

Maintainer: Shadofer#0001

Contributors: 

File description:
    Utilities of the server of TowerVerse.

Extra info:
    None
"""

""" BUILT-IN MODULES """

""" Specifying variable types. """
from typing import List

""" Checking letters, generating IDs. """
from random import choice
from string import ascii_letters, ascii_uppercase, digits, whitespace

""" Logging. """
from logging import getLogger

""" 3RD-PARTY MODULES """

""" Validating emails. """
from email_validator import EmailNotValidError, validate_email

""" LOCAL MODULES """

from towerverseserver.constants import *

""" GLOBAL VARIABLES """

""" The logger of the server. """
log = getLogger(LOGGER_NAME)

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

def check_loop_data(data: dict, keys: List[str]) -> str:
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
            continue

    if keys_needed:
        result_response = 'Data must contain '

        for key in keys_needed:
            result_to_append = ''

            if keys_needed[0] == key:
                result_to_append = key

            elif keys_needed[-1] == key:
                result_to_append = f' and {key}.'

            else:
                result_to_append = f', {key}'

            result_response += result_to_append

        return result_response

def gen_id() -> str:
    """Generates an ID with 15 digits for use when creating an account.

    Returns:
        str: The resulting ID.
    """
    result_id = ''

    for i in range(15):
        result_id += str(choice(f'{ascii_letters}{digits}'))

    return result_id

def gen_verification_code() -> str:
    """Generates a verification code with length VERIFICATION_CODE_LENGTH.

    Returns:
        str: The verification code.
    """
    
    verification_code = ''
    
    for i in range(VERIFICATION_CODE_LENGTH):
        verification_code += str(choice(digits))

    return verification_code

def log_error(print_msg: str, exc: Exception) -> None:
    """Prints an error and continues normal execution of the program.

    Args:
        print_msg (str): The message to log.
        exc (Exception): The exception to log below the print_msg.
    """
    if isinstance(exc, Exception):
        log.error(f'{print_msg}: \n{exc.__class__.__name__}: {exc}')
    else:
        log.warn('Invalid exception passed to print_error, aborting operation.')

def log_error_and_exit(exit_msg: str, exc: Exception) -> None:
    """Prints an error and forcefully exits program execution. ONLY FOR DESTRUCTIVE EXCEPTIONS.

    Args:
        exit_msg (str): The message to log.
        exc (Exception): The exception to log below the exit_msg.
    """
    if isinstance(exc, Exception):
        log.error(f'{exit_msg}, exiting: \n{exc.__class__.__name__}: {exc}')
        exit()
    else:
        log.warn('Invalid exception passed to print_error_and_exit, aborting operation.')

def format_password(password: str) -> str:
    """Formats a provided password for checking later on with check_password.

    Args:
        password (str): The target password.

    Returns:
        str: The formatted password.
    """
    return ''.join([letter for letter in password if letter not in whitespace])

def check_password(password: str) -> list:
    """Tests a password with multiple cases. Should be used in combination with format_password.

    Args:
        password (str): The target password.

    Returns:
        list: The error, if one occured, where: [0] the name of the error and [1] the description of the error.
    """
    if not check_length(password, MIN_PASS_LENGTH, MAX_PASS_LENGTH):
        return ['PasswordExceedsLimit', f'Traveller password must be between {MIN_PASS_LENGTH} and {MAX_PASS_LENGTH} characters long.']

def check_email(email: str) -> EmailNotValidError:
    """Checks if an email has a valid format.

    Args:
        email (str): The target email.

    Returns:
        EmailNotValidError: The error, if any, which is thrown by email_validator.
    """
    try:
        validate_email(email)
    except EmailNotValidError as e:
        return e

def check_chars(target: str, target_chars: str) -> bool:
    """Checks if the target string only contains target characters.

    Args:
        target (str): The target string.
        target_chars (str): The target characters.

    Returns:
        bool: Whether or not it contains unknown characters.
    """
    return len([letter for letter in target if letter not in target_chars]) == 0

def check_length(target: str, min: int, max: int) -> bool:
    """Checks if the target string's length is appropriate.

    Args:
        target (str): The target string.
        min (int): The minimum length.
        max (int): The maximum length.

    Returns:
        bool: Whether or not it comes between the two limits.
    """
    return len(target) >= min and len(target) <= max
