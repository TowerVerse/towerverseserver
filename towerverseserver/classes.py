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
from dataclasses import dataclass, field

""" Specifying variable types. """
from typing import List

@dataclass(frozen=False)
class Traveller():
    """The base `Traveller` instance. """
    traveller_id: str
    traveller_name: str
    traveller_email: str
    traveller_password: bytes
    has_changed_name: bool
    is_in_guild: bool
    guild_id: str

@dataclass(frozen=False)
class TempTraveller(Traveller):
    """The base `TempTraveller` instance, used for a temporary account before verification. """
    traveller_code: str

@dataclass(frozen=False)
class Guild():
    """The base `Guild` instance. """
    guild_id: str
    guild_name: str
    guild_description: str
    guild_creator: str
    guild_visibility: str
    guild_max_members: str
    guild_members: List[str] = field(default_factory=list)
    guild_banned_members: List[str] = field(default_factory=list)

@dataclass(frozen=False)
class Tower():
    """The base `Tower` instance. """
    tower_id: str
    tower_name: str
    tower_creator: str
    tower_visibility: bool = True
    