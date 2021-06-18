from dataclasses import dataclass


def check(items: dict):
    for item, type in items:
        assert isinstance(item, type)


@dataclass(frozen=True)
class Tower():
    """The base Tower instance. """
    tower_id: str
    tower_name: str
    tower_creator: int
    tower_visibility: bool = True


@dataclass(frozen=True)
class Traveller():
    """The base Traveller instance. """
    traveller_id: int
    traveller_name: str
    traveller_email: str
    traveller_password: str
