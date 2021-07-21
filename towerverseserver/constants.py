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
from string import ascii_letters, digits, punctuation

""" ONLY USED FOR THE LOCAL VERSION """

""" Max requests until the IP is ratelimited. """
IP_RATELIMIT_MAX = 200

""" Seconds between resetting every IP's ratelimit requests to 0. """
IP_RATELIMIT_CLEANUP_INTERVAL = 60 # every minute

""" Seconds between emptying the IP requests dictionary. """
IP_REQUESTS_CLEANUP_INTERVAL = 60 * 60 # every hour

""" Seconds between resetting IP account links. """
IP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24 # every day

""" Seconds between resetting accounts which aren't verified. """
TEMP_ACCOUNT_CLEANUP_INTERVAL = 60 * 60 * 24 * 7 # every week

""" Account-related. """
USERNAME_CHARACTERS = f'{ascii_letters}{digits}!^*'
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 20

EMAIL_CHARACTERS = f'{ascii_letters}{digits}@.'
MIN_EMAIL_LENGTH = 10
MAX_EMAIL_LENGTH = 60

PASSWORD_CHARACTERS = ascii_letters + digits + '`~!@#$%^&*()-_=+[{]}\|;:\'",<.>/?'
MIN_PASS_LENGTH = 10
MAX_PASS_LENGTH = 50

VERIFICATION_CODE_LENGTH = 6

""" Guild-related. """
GUILD_NAME_CHARACTERS = f'{ascii_letters}{digits}{punctuation} '
MIN_GUILD_NAME_LENGTH = 5
MAX_GUILD_NAME_LENGTH = 25

GUILD_DESCRIPTION_CHARACTERS = f'{ascii_letters}{digits}{punctuation} '
MIN_GUILD_DESCRIPTION_LENGTH = 1
MAX_GUILD_DESCRIPTION_LENGTH = 100

MAX_GUILD_MAX_MEMBERS_NUMBER = 10

""" Log related. """
LOGGER_NAME = 'towerverse-server'

""" MongoDB-related. """
mongo_project_name = 'towerverse.kx1he'
mongo_database_name = 'towerverse-db'
mongo_client_extra_args = 'retryWrites=true&w=majority'

""" String templates. """
length_invalid = '{} should consist of {} to {} characters.'
length_specific_invalid = '{} should be between {} and {}.'
chars_invalid = '{} contains invalid characters.'
argument_invalid_type = '{} is of incorrect type. Target type must be {}.'
email_title = 'TowerVerse {}'
email_content_code = 'This is your TowerVerse {} code: '
email_content_changed = 'Your Towerverse {} has been changed successfully.'
strf_format = '%d/%m/%Y %H:%M'
wrapper_alr_exists = 'The {} named "{}" already exists, aborting operation.'
