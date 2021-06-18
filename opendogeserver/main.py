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

""" 3RD-PARTY MODULES """

""" The main way of communicating. """
from websockets import serve as ws_serve

""" LOCAL MODULES """
from opendogeserver.constants import IS_LOCAL
from opendogeserver.server import Server
from opendogeserver.auth import AccountHandler

if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    print(f"Server type: {'PRODUCTION' if not IS_LOCAL else 'LOCAL'}")

    server = Server()

    if not IS_LOCAL:
        if not 'OPENDOGE_MONGODB_USERNAME' in environ and not 'OPENDOGE_MONGODB_PASSWORD' in environ:
            print('MongoDB variables must either be passed to the start function or set to the environmental variables: OPENDOGE_MONGODB_USERNAME, OPENDOGE_MONGODB_PASSWORD for the production server to function!')
            exit()
        else:
            mdb = server.setup_mongo(environ['OPENDOGE_MONGODB_USERNAME'], environ['OPENDOGE_MONGODB_PASSWORD'])
    else:
        mdb = None

    server = Server(mdb)

    """ Register events """
    auth = AccountHandler(server)

    """ Heroku expects us to bind on a specific port, if deployed locally we can bind anywhere. """
    port = environ.get('PORT', 5000)

    start_server = ws_serve(server.serve, '0.0.0.0', port)

    """ Dynamically find and start server tasks. """
    registered_tasks = [task for task_name, task in globals(
    ).items() if task_name.startswith('task_')]

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
