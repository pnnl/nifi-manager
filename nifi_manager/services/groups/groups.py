from typing import FrozenSet
from models import NifiGroup, NifiMember, NifiGroupSet, NifiMemberSet
from config import Config, get_config
from utils import get, post, put, delete

CONFIG: Config = get_config()
URL = CONFIG.url + CONFIG.groups_path


class GroupNotCreated(Exception):
    pass


class GroupExists(Exception):
    pass


class GroupNotExists(Exception):
    pass


class GroupNotUpdated(Exception):
    pass


class GroupNotDeleted(Exception):
    pass


def get_all_groups() -> FrozenSet[NifiGroup]:
    response = get(URL, CONFIG)
    try:
        status_code = response.status_code
        if status_code == 200:
            return NifiGroupSet.validate_python(
                response.json().get("userGroups", set())
            )
        else:
            raise ValueError(f"response code not 200: {status_code}")

    except Exception:
        raise ValueError("something went wrong")


def get_group(group_id: str) -> NifiGroup:
    response = get(URL + f"/{group_id}", CONFIG)
    try:
        status_code = response.status_code
        if status_code == 200:
            return NifiGroup.model_validate_json(response.text)
        else:
            raise ValueError(f"response code not 200: {status_code}")

    except Exception:
        raise ValueError("something went wrong")


def create_group(identity: str, users: FrozenSet[NifiMember]) -> NifiGroup:
    payload = {
        "revision": {"version": 0},
        "component": {
            "identity": identity,
            "users": NifiMemberSet.dump_python(users, mode="json"),
        },
    }

    response = post(URL, CONFIG, payload)
    if response.status_code in (200, 201):
        return NifiGroup.model_validate_json(response.text)
    elif response.status_code == 409:
        raise GroupExists(f"group {identity} already exists and could not be created")

    raise GroupNotCreated(
        f"group {identity} could not be created: {response.text}, status_code: {response.status_code}"
    )


def update_group(group: NifiGroup, users: FrozenSet[NifiMember]) -> NifiGroup:
    payload = {
        "revision": {"version": group.revision.version},
        "component": {
            "id": group.id,
            "identity": group.identity,
            "users": NifiMemberSet.dump_python(users, mode="json"),
        },
    }

    response = put(URL + f"/{group.id}", CONFIG, payload)
    if response.status_code in (200, 201):
        return NifiGroup.model_validate_json(response.text)
    elif response.status_code == 404:
        raise GroupNotExists(f"group {group.identity} does not exist")
    else:
        raise GroupNotUpdated(
            f"group {group.identity} could not be updated: {response.text}"
        )


def delete_group(group: NifiGroup):
    response = delete(URL + f"/{group.id}?version={group.revision.version}", CONFIG)

    if response.status_code != 200:
        raise GroupNotDeleted(f"could not delete group {group.id}")
