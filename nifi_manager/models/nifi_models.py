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
###                 Validation                 ###
##################################################


def _ensure_leading_slash(resource: str) -> str:
    stripped = resource.strip().lstrip("/")
    if not stripped:
        raise ValueError("policy resource cannot be empty")
    return f"/{stripped}"


APIPolicyResource = Annotated[
    str,
    "ensure that the resource object always begins with '/'",
    BeforeValidator(_ensure_leading_slash),
]


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

    resource: APIPolicyResource = Field(
        validation_alias=AliasPath("component", "resource")
    )
    action: NifiPolicyAction = Field(validation_alias=AliasPath("component", "action"))
    users: FrozenSet[NifiUser] = Field(validation_alias=AliasPath("component", "users"))
    user_groups: FrozenSet[NifiGroup] = Field(
        validation_alias=AliasPath("component", "userGroups")
    )

    model_config = ConfigDict(populate_by_name=True)


def resource_to_member(resource: NifiResource) -> NifiMember:
    return NifiMember(id=resource.id)


NifiUserSet = TypeAdapter(FrozenSet[NifiUser])
NifiGroupSet = TypeAdapter(FrozenSet[NifiGroup])
NifiPolicySet = TypeAdapter(FrozenSet[NifiPolicy])
NifiMemberSet = TypeAdapter(FrozenSet[NifiMember])
