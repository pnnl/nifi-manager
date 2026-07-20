"""Pydantic models to verify input and output of this script"""

from pydantic import BaseModel, field_validator
from typing import FrozenSet, Annotated, Literal
from .nifi_models import (
    NifiPolicyAction,
    APIPolicyResource,
)

##################################################
###              Function Models               ###
##################################################


class Policy(BaseModel, frozen=True):
    resource: APIPolicyResource
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


_changes = Literal["ADDED", "REMOVED", "UPDATED"]
ChangeEffect = Annotated[
    _changes,
    "list of effects of a change that can occur in the ACL",
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
