from pymongo.database import Database
from pymongo import MongoClient
from sys import argv

mongo_project_name = 'opendoge'
mongo_database_name = 'opendoge-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'
mdbclient: MongoClient = None

IS_LOCAL = '--local' in argv

""" Max requests until IP ratelimits are cleared. """
IP_RATELIMIT_MAX = 10
