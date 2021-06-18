"""

Made by Shadofer#0001.
Pass --local in order to disable database-related methods. Otherwise set environmental variables for MongoDB.

"""

from os import environ
import asyncio

from websockets import serve as ws_serve
from socket import gethostname, gethostbyname, gaierror

from constants import IS_LOCAL
from server import Server, setup_mongo
from auth import AccountHandler

if __name__ == '__main__':
	loop = asyncio.get_event_loop()

	print(f"Server type: {'PRODUCTION' if not IS_LOCAL else 'LOCAL'}")

	if not IS_LOCAL:
		if not 'OPENDOGE_MONGODB_USERNAME' in environ and not 'OPENDOGE_MONGODB_PASSWORD' in environ:
			print('MongoDB variables must either be passed to the start function or set to the environmental variables: OPENDOGE_MONGODB_USERNAME, OPENDOGE_MONGODB_PASSWORD for the production server to function!')
			exit()
		else:
			mdb = setup_mongo(environ['OPENDOGE_MONGODB_USERNAME'], environ['OPENDOGE_MONGODB_PASSWORD'])
	else:
		mdb = None

	server = Server(mdb)

	""" Register events """
	auth = AccountHandler(server)

	""" Heroku expects us to bind on a specific port, if deployed locally we can bind anywhere. """
	port = environ.get('PORT', 5000)

	start_server = ws_serve(server.serve, '0.0.0.0', port)

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
