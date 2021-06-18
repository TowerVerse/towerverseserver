"""

    Shadofer#0001 and Otterlord#3653
    Copyright GPL-3

"""

""" BUILT-IN MODULES """

""" Get command-line arguments. """
from sys import argv

""" 3RD-PARTY MODULES """

""" Production server MongoDB. """
from pymongo import MongoClient

mongo_project_name = 'opendoge'
mongo_database_name = 'opendoge-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'
mdbclient: MongoClient = None

IS_LOCAL = '--local' in argv

""" Max requests until IP ratelimits are cleared. """
IP_RATELIMIT_MAX = 10
