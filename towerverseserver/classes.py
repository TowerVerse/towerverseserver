""" 
License: GPL-3

Maintainer: Shadofer#0001

Contributors: 

File description:
    The classes of the server of TowerVerse.

Extra info:
    None
"""

""" BUILT-IN MODULES """

""" A better way to use classes. """
from dataclasses import dataclass

@dataclass(frozen=True)
class Tower():
    """The base `Tower` instance. """
    tower_id: str
    tower_name: str
    tower_creator: str
    tower_visibility: bool = True

@dataclass(frozen=True)
class Traveller():
    """The base `Traveller` instance. """
    traveller_id: str
    traveller_name: str
    traveller_email: str
    traveller_password: str

@dataclass(frozen=True)
class TempTraveller(Traveller):
    """The base `TempTraveller` instance, used for a temporary account before verification. """
    traveller_code: str
