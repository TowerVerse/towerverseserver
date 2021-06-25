""" 
License: GPL-3

Maintainer: Shadofer#0001

Contributors: 

File description:
    The constant variables of the server of TowerVerse.

Extra info:
    None
"""

""" BUILT-IN MODULES """

""" Character limits. """
from string import ascii_letters, digits

""" ONLY USED FOR THE LOCAL VERSION """

""" Max requests until IP ratelimits are cleared. """
IP_RATELIMIT_MAX = 10

""" Seconds between resetting IP ratelimits. """
IP_RATELIMIT_CLEANUP_INTERVAL = 5

""" Seconds between resetting IP requests. """
IP_REQUESTS_CLEANUP_INTERVAL = 60 * 60 # every minute

""" Seconds between resetting IP account links. """
IP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24 # every day

""" Seconds between resetting accounts which aren't verified. """
TEMP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24 * 7 # every week

""" Account-related. """
ACCOUNT_CHARACTERS = f'{ascii_letters}{digits}!^* '
MIN_ACCOUNT_LENGTH = 3
MAX_ACCOUNT_LENGTH = 20

EMAIL_CHARACTERS = f'{ascii_letters}{digits}@.'
MIN_EMAIL_LENGTH = 10
MAX_EMAIL_LENGTH = 60

MIN_PASS_LENGTH = 10
MAX_PASS_LENGTH = 50

VERIFICATION_CODE_LENGTH = 6

""" MongoDB-related. """
mongo_project_name = 'towerverse.kx1he'
mongo_database_name = 'towerverse-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'
