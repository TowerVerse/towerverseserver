from setuptools import setup

setup(
    name = 'towerverseserver',
    version = '0.3a1',
    description = 'The server of TowerVerse, only used for development purposes.',
    author = 'Shadofer#0001',
    author_email = 'shadowrlrs@gmail.com',
    python_requires = '>=3.7.0',
    url = 'https://github.com/TowerVerse/towerverseserver',
    packages = ['towerverseserver'],
    install_requires = ['websockets==10.3', 'email_validator==1.1.3', 'bcrypt==3.2.0', 'pymongo==3.11.4', 'aioyagmail==0.0.4', 'python-dotenv==0.19.0'],
    extras_require = {'tests':
                        ['pytest==6.2.4', 'pytest-asyncio==0.15.1', 'pytest-ordering==0.6']
                    },
    license = 'GPL-3'
)
