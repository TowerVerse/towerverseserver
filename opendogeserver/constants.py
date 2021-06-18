"""

    Shadofer#0001 and Otterlord#3653
    Copyright GPL-3

"""

""" MongoDB specifications. """
mongo_project_name = 'opendoge'
mongo_database_name = 'opendoge-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'

""" Max requests until IP ratelimits are cleared. """
IP_RATELIMIT_MAX = 10

""" Seconds between resetting IP ratelimits. """
IP_RATELIMIT_CLEANUP_INTERVAL = 5

""" Seconds between resetting IP requests. """
IP_REQUESTS_CLEANUP_INTERVAL = 60 * 60

""" Seconds between resetting IP account links. """
IP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24

""" Account-related. """
MIN_ACCOUNT_NAME = 3
MAX_ACCOUNT_NAME = 20
MIN_PASS_LENGTH = 8
MAX_PASS_LENGTH = 20
