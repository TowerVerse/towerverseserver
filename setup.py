from setuptools import setup

setup(
    name = 'opendogeserver',
    version = '0.2a1',
    description = 'The server of opendoge, only used for development purposes.',
    author = 'Shadofer#0001',
    author_email = 'shadowrlrs@gmail.com',
    python_requires = '>=3.7.0',
    url = 'https://github.com/OpenDoge/opendogeserver',
    packages = ['opendogeserver'],
    install_requires = ['websockets==9.1', 'email_validator==1.1.3', 'bcrypt==3.2.0', 'pymongo==3.11.4'],
    extras_require = {'tests':
                        ['pytest==6.2.4', 'pytest-asyncio==0.15.1', 'pytest-ordering==0.6']
                    },
    license = 'GPL-3'
)