"""Pydantic models for return object from NIFI's API"""

from pydantic import (
    AliasPath,
    BaseModel,
    BeforeValidator,
    Field,
    ConfigDict,
    TypeAdapter,
)
from typing import Annotated, FrozenSet, Literal

##################################################
###                 Nifi Models                ###
##################################################


class NifiRevisionInfo(BaseModel, frozen=True):
    """Revision tracking for optimistic locking"""

    version: int = 0

    model_config = ConfigDict(populate_by_name=True)


class NifiResource(BaseModel, frozen=True):
    """Object containing id of a NIFI resource"""

    id: str
    revision: NifiRevisionInfo


class NifiNamedComponent(BaseModel, frozen=True):
    """Component base class for components with human readable names"""

    id: str
    identity: str


class NifiMember(BaseModel, frozen=True):
    """Base class for each member passed to a membership list like users and groups"""

    id: str
    model_config = ConfigDict(populate_by_name=True)


_nifi_actions = Literal["read", "write"]
NifiPolicyAction = Annotated[
    _nifi_actions,
    BeforeValidator(lambda a: a if isinstance(a, str) else a),
    "self-validating class for allowed actions in nifi policy list",
]


class NifiGroup(NifiResource, frozen=True):
    """NiFi User Group entity"""

    identity: str = Field(validation_alias=AliasPath("component", "identity"))
    users: FrozenSet["NifiUser"] = Field(
        default=frozenset(), validation_alias=AliasPath("component", "users")
    )
    model_config = ConfigDict(populate_by_name=True)


class NifiUser(NifiResource, frozen=True):
    """NiFi User entity"""

    identity: str = Field(validation_alias=AliasPath("component", "identity"))

    model_config = ConfigDict(populate_by_name=True)


class NifiPolicy(NifiResource, frozen=True):
    """NiFi Access Policy entity"""

    resource: str = Field(validation_alias=AliasPath("component", "resource"))
    action: NifiPolicyAction = Field(validation_alias=AliasPath("component", "action"))
    users: FrozenSet[NifiUser] = Field(validation_alias=AliasPath("component", "users"))
    user_groups: FrozenSet[NifiGroup] = Field(
        validation_alias=AliasPath("component", "userGroups")
    )

    model_config = ConfigDict(populate_by_name=True)


NifiUserSet = TypeAdapter(FrozenSet[NifiUser])
NifiGroupSet = TypeAdapter(FrozenSet[NifiGroup])
NifiPolicySet = TypeAdapter(FrozenSet[NifiPolicy])
NifiMemberSet = TypeAdapter(FrozenSet[NifiMember])
