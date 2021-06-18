from sys import argv
from uuid import uuid4

from pymongo.database import Database
from pymongo import MongoClient

IS_LOCAL = '--local' in argv

mongo_project_name = 'opendoge'
mongo_database_name = 'opendoge-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'
mdbclient: MongoClient = None
mdb: Database = None

""" Max requests until IP ratelimits are cleared. """
IP_RATELIMIT_MAX = 10
