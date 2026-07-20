from typing import FrozenSet, List, Dict, Tuple, Optional
from models import (
    NifiGroup,
    NifiMember,
    NifiGroupSet,
    NifiMemberSet,
    Group,
    GroupChange,
)
from config import Config, get_config
from methods import get, post, put, delete
import logging

logger = logging.getLogger("Policy Service")

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


def get_existing_groups() -> Dict[str, NifiGroup]:
    all_groups = _get_all_groups()

    groups = {}
    for group in all_groups:
        groups[group.identity] = group

    return groups


def sync_group(
    group: Group,
    existing_group: Optional[NifiGroup],
    user_list: FrozenSet[NifiMember],
    dry_run: bool,
) -> Tuple[Optional[NifiGroup], Optional[GroupChange]]:
    try:
        if not existing_group:
            change = GroupChange(change="ADDED", group=group)
            if dry_run:
                logger.info(f"would create group {group.identity}")
                return existing_group, change
            created_group = _create_group(
                group.identity,
                user_list,
            )
            return created_group, change

        existing_users = frozenset(
            {NifiMember(id=user.id) for user in existing_group.users}
        )

        if existing_users != user_list:
            change = GroupChange(change="UPDATED", group=group)
            if dry_run:
                logger.info(f"would update group {group.identity}")
                return existing_group, change

            updated_group = _update_group(
                existing_group,
                user_list,
            )
            return updated_group, change

        return existing_group, None
    except GroupNotCreated as e:
        logger.warning(f"group not created: {e}")
        raise
    except GroupNotUpdated as e:
        logger.warning(f"group not updated: {e}")
        raise
    except GroupExists:
        logger.warning(
            f"group {group.identity} already exists but we tried to create it..."
        )
        raise


def del_non_acl_groups(
    to_delete: FrozenSet[NifiGroup], dry_run: bool
) -> Tuple[List[GroupChange], List[Exception]]:
    changes: List[GroupChange] = []
    failures: List[Exception] = []
    for group in to_delete:
        try:
            if dry_run:
                logger.info(f"would delete group {group.identity}")
                changes.append(_get_group_removal_change(group))
                continue

            logger.info(f"deleting group: {group.identity}")
            change = _delete_group(group)
            changes.append(change)
        except Exception as e:
            logger.warning(e)
            failures.append(e)

    return changes, failures


def _get_group_removal_change(group: NifiGroup) -> GroupChange:
    return GroupChange(
        change="REMOVED",
        group=Group(identity=group.identity, users=frozenset()),
    )


def _get_all_groups() -> FrozenSet[NifiGroup]:
    response = get(URL, CONFIG.certs, CONFIG.verify, CONFIG.ca_cert_path)
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


def _create_group(identity: str, users: FrozenSet[NifiMember]) -> NifiGroup:
    payload = {
        "revision": {"version": 0},
        "component": {
            "identity": identity,
            "users": NifiMemberSet.dump_python(users, mode="json"),
        },
    }

    response = post(URL, CONFIG.certs, CONFIG.verify, CONFIG.ca_cert_path, payload)
    if response.status_code in (200, 201):
        return NifiGroup.model_validate_json(response.text)
    elif response.status_code == 409:
        raise GroupExists(f"group {identity} already exists and could not be created")

    raise GroupNotCreated(
        f"group {identity} could not be created: {response.text}, status_code: {response.status_code}"
    )


def _update_group(group: NifiGroup, users: FrozenSet[NifiMember]) -> NifiGroup:
    payload = {
        "revision": {"version": group.revision.version},
        "component": {
            "id": group.id,
            "identity": group.identity,
            "users": NifiMemberSet.dump_python(users, mode="json"),
        },
    }

    response = put(
        URL + f"/{group.id}", CONFIG.certs, CONFIG.verify, CONFIG.ca_cert_path, payload
    )
    if response.status_code in (200, 201):
        return NifiGroup.model_validate_json(response.text)
    elif response.status_code == 404:
        raise GroupNotExists(f"group {group.identity} does not exist")
    else:
        raise GroupNotUpdated(
            f"group {group.identity} could not be updated: {response.text}"
        )


def _delete_group(group: NifiGroup) -> GroupChange:
    response = delete(
        URL + f"/{group.id}?version={group.revision.version}",
        CONFIG.certs,
        CONFIG.verify,
        CONFIG.ca_cert_path,
    )

    if response.status_code != 200:
        raise GroupNotDeleted(f"could not delete group {group.id}")

    return GroupChange(
        change="REMOVED",
        group=Group(
            identity=group.identity,
            users=frozenset(),
        ),
    )
