"""

    Shadofer#0001 and Otterlord#3653
    Copyright GPL-3

"""

""" BUILT-IN MODULES """

""" Parsing responses. """
from json import dumps

""" Specifying variables types. """
from typing import List

""" Checking letters. """
from string import ascii_uppercase

def to_snake_case(event: str, is_argument: bool = False) -> str:
    """Transforms a python string to an event/argument name.

    Args:
        event (str): The event.
        is_argument (bool): Whether or not it's going to be passed as an argument. Defaults to False.

    Returns:
        str: The formatted string.
    """
    target_list = list(event)

    for index, letter in enumerate(target_list):
        if letter in ascii_uppercase:
            target_list[index] = letter.lower()
            target_list.insert(index, '_')

    result = ''.join([letter for letter in target_list])

    return f"event_{result}" if not is_argument else result

def to_camel_case(event: str) -> str:
    """Transforms an argument which was modified by to_snake_case to its original state.

    Args:
        event (str): The argument to restore.

    Returns:
        str: The restored agument.
    """
    target_list = list(event)

    for index, letter in enumerate(target_list):
        if letter == '_':
            target_list.pop(index)
            target_list[index] = target_list[index].upper()

    return ''.join([letter for letter in target_list])

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
            keys_needed.append(to_camel_case(key))
            continue

        try:
            if len(data[key].strip()) == 0:
                return f'{key} value mustn\'t be empty.'
        except AttributeError:
            """ WebSocketServerProtocol probably, passed by default in functions which ask for it. """
            continue

    """ Much better visualization by showing them all at once. """
    if keys_needed:
        return f'Data must contain {" and ".join([key for key in keys_needed])}.'
    return None

def format_res(event_name: str, event_reply: str = 'Reply', ref: str = None, **kwargs) -> str:
    """Formats a response to be sent in an appropriate form, with optional keyword arguments.

    Args:
        event_name (str): The name of the event.
        event_reply (str): The string to concatenate to the event_name which will be the reply. Defaults to Reply.
        ref (str): Optional. The ref passed to the request.

    Returns:
        dict: The formatted response.
    """
    result_data = dict(data=kwargs, event=f'{event_name}{event_reply}', originalEvent=event_name)

    if ref:
        result_data['ref'] = ref

    return dumps(result_data)

def format_res_err(event_name: str, event_reply: str, error_message: str, is_no_event_response: bool = False, ref: str = None, **kwargs) -> str:
    """Same as above but for errors.

    Args:
        event_name (str): The name of the event. Set to '' so as not to pass originalEvent to the response.
        event_reply (str): The string to concatenate to the event_name which will be the reply.
        error_message (str): The message of the error.
        is_no_event_response (bool): If True, event_reply wont be concatenated to event_name. This is helpful for general errors.
        ref (str): Optional. The ref passed to the request.

    Returns:
        dict: The formatted error response.
    """

    result_data = dict(data={'errorMessage': error_message, **kwargs}, event=f'{event_name}{event_reply}' if not is_no_event_response else f'{event_reply}',
                       originalEvent=event_name)

    if ref:
        result_data['ref'] = ref

    return dumps(result_data)
