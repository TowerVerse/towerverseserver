"""

    Shadofer#0001 and Otterlord#3653
    Copyright GPL-3

"""

""" BUILT-IN MODULES """

""" Better way for using classes. """
from dataclasses import dataclass

@dataclass(frozen=True)
class Traveller():
    """The base `Traveller` instance. """
    traveller_id: int
    traveller_name: str
    traveller_email: str
    traveller_password: str
    
@dataclass(frozen=True)
class Tower():
    """The base `Tower` instance. """
    tower_id: str
    tower_name: str
    tower_creator: int
    tower_visibility: bool = True
