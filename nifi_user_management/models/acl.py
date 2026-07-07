"""Pydantic models to verify input and output of this script"""

from pydantic import BaseModel, BeforeValidator, field_validator
from typing import FrozenSet, Dict, Annotated, Literal
from .nifi_models import NifiGroup, NifiPolicy, NifiPolicyAction, NifiUser

##################################################
###              Function Models               ###
##################################################


class Policy(BaseModel, frozen=True):
    resource: str
    action: NifiPolicyAction
    users: FrozenSet[str]
    groups: FrozenSet[str]

    @field_validator("action")
    @classmethod
    def check_action(cls, value: str) -> str:
        if value != "read" and value != "write":
            raise ValueError("action can only be 'read' or 'write'")
        return value


class User(BaseModel, frozen=True):
    identity: str


class Group(BaseModel, frozen=True):
    identity: str
    users: FrozenSet[str]


class ACLList(BaseModel, frozen=True):
    users: FrozenSet[User]
    groups: FrozenSet[Group]
    policies: FrozenSet[Policy]


class ExistingACL(BaseModel):
    users: Dict[str, NifiUser]
    groups: Dict[str, NifiGroup]
    policies: Dict[str, NifiPolicy]


_changes = Literal["ADDED", "REMOVED", "UPDATED"]
ChangeEffect = Annotated[
    _changes,
    "list of effects of a change that can occur in the ACL",
    BeforeValidator(lambda c: c if isinstance(c, str) else c),
]


class Change(BaseModel):
    """base pydantic model for polymorphism"""

    change: ChangeEffect


class UserChange(Change):
    """pydantic model to validate the list of users that have changed"""

    user: User

    def __str__(self) -> str:
        return f"{self.change:<8} User: {self.user.identity}"


class GroupChange(Change):
    group: Group

    def __str__(self) -> str:
        return f"{self.change:<8} Group: {self.group.identity}, Members: {list(self.group.users)}"


class PolicyChange(Change):
    policy: Policy

    def __str__(self) -> str:
        return f"{self.change:<8} Policy: {self.policy.action} on {self.policy.resource}, Members: Users: {list(self.policy.users)}, Groups: {list(self.policy.groups)}"
