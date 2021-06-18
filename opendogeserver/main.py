"""

    Shadofer#0001 and Otterlord#3653
    Copyright GPL-3
    Pass --local in order to disable database-related methods. Otherwise set environmental variables for MongoDB.

"""

""" BUILT-IN MODULES """
import asyncio

""" Getting environmental variables. """
from os import environ

""" Getting network-related info. """
from socket import gethostname, gethostbyname, gaierror

""" Get command-line arguments. """
from sys import argv

""" Specifying variable types. """
from typing import List

""" Inspecting functions. """
from inspect import getmembers, ismethod

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets import serve as ws_serve

""" LOCAL MODULES """
from opendogeserver.server import Server
from opendogeserver.accounts import AccountHandler

if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    IS_LOCAL = '--local' in argv

    print(f"Server type: {'PRODUCTION' if not IS_LOCAL else 'LOCAL'}")

    server = Server()
    server.IS_LOCAL = IS_LOCAL
    
    """ Register events. """
    accounts_obj = AccountHandler()
    account_events = [event for event_name, event in dict(getmembers(accounts_obj, ismethod)).items() if event_name.startswith('event_')]

    """ Uncomment this and comment the line below that one when adding more files with different kinds of events. """
    #all_events = account_events.extend()
    all_events = account_events
    
    for event in all_events:
        server.events[event.__name__] = event

    if not IS_LOCAL:
        if not 'OPENDOGE_MONGODB_USERNAME' in environ and not 'OPENDOGE_MONGODB_PASSWORD' in environ:
            print('MongoDB variables must either be passed to the start function or set to the environmental variables: OPENDOGE_MONGODB_USERNAME, OPENDOGE_MONGODB_PASSWORD for the production server to function!')
            exit()
        else:
            mdb = server.setup_mongo(environ['OPENDOGE_MONGODB_USERNAME'], environ['OPENDOGE_MONGODB_PASSWORD'])

    """ Dynamically find and start server tasks. """
    registered_tasks = [task for task_name, task in dict(getmembers(server, ismethod)).items() if task_name.startswith('task_')]

    for task in registered_tasks:
        loop.create_task(task())

    if len(registered_tasks) > 0:
        print('Tasks started.')
        
    """ Heroku expects us to bind on a specific port, if deployed locally we can bind anywhere. """
    port = environ.get('PORT', 5000)

    start_server = ws_serve(server.serve, '0.0.0.0', port)
    
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
