from pydantic import TypeAdapter
from typing import FrozenSet, List, Dict, Optional, Tuple
from models import NifiUser, User, UserChange
from config import Config, get_config
from methods import get, post, delete
import logging

logger = logging.getLogger("User Service")

CONFIG: Config = get_config()
URL = CONFIG.url + CONFIG.users_path


class UserNotCreated(Exception):
    pass


class UserExists(Exception):
    pass


class UserNotDeleted(Exception):
    pass


def get_existing_users() -> Dict[str, NifiUser]:
    all_users = _get_all_users()

    users = {}
    for user in all_users:
        users[user.identity] = user

    return users


def sync_user(
    user: User,
    existing_user: Optional[NifiUser],
    dry_run: bool,
) -> Tuple[Optional[NifiUser], Optional[UserChange]]:
    try:
        if not existing_user:
            change = UserChange(change="ADDED", user=user)
            if dry_run:
                logger.info(f"would create user {user.identity}")
                return existing_user, change
            created_user = _create_user(
                user.identity,
            )
            return created_user, change

        return existing_user, None
    except UserNotCreated as e:
        logger.warning(f"user not created: {e}")
        raise
    except UserExists:
        logger.warning(
            f"user {user.identity} already exists but we tried to create it..."
        )
        raise


def del_non_acl_users(
    to_delete: FrozenSet[NifiUser], dry_run: bool
) -> Tuple[List[UserChange], List[Exception]]:
    changes: List[UserChange] = []
    failures: List[Exception] = []
    for user in to_delete:
        try:
            if dry_run:
                logger.info(f"would delete user {user.identity}")
                changes.append(_get_user_removal_change(user))
                continue

            logger.info(f"deleting user: {user.identity}")
            change = _delete_user(user)
            changes.append(change)
        except Exception as e:
            logger.warning(e)
            raise

    return changes, failures


def _get_user_removal_change(user: NifiUser) -> UserChange:
    return UserChange(
        change="REMOVED",
        user=User(identity=user.identity),
    )


def _get_all_users() -> List[NifiUser]:
    response = get(URL, CONFIG.certs, CONFIG.verify, CONFIG.ca_cert_path)
    try:
        status_code = response.status_code
        ta = TypeAdapter(List[NifiUser])
        if status_code == 200:
            return ta.validate_python(response.json().get("users", []))
        else:
            raise ValueError(f"response code not 200: {status_code}")

    except Exception:
        raise ValueError("something went wrong")


def _create_user(identity: str) -> NifiUser:
    payload = {"revision": {"version": 0}, "component": {"identity": identity}}

    response = post(URL, CONFIG.certs, CONFIG.verify, CONFIG.ca_cert_path, payload)
    if response.status_code in (200, 201):
        user = NifiUser.model_validate_json(response.text)
        if not user:
            raise UserNotCreated(
                f"user {identity} could not be created: {response.text}, status_code: {response.status_code}"
            )
        return user
    elif response.status_code == 409:
        raise UserExists(f"user {identity} already exists and could not be created")
    raise UserNotCreated(
        f"user {identity} could not be created: {response.text}, status_code: {response.status_code}"
    )


def _delete_user(user: NifiUser):
    response = delete(
        URL + f"/{user.id}?version={user.revision.version}",
        CONFIG.certs,
        CONFIG.verify,
        CONFIG.ca_cert_path,
    )

    if response.status_code != 200:
        raise UserNotDeleted(
            f"could not delete user {user.id}: {response.text}, status_code: {response.status_code}"
        )

    return _get_user_removal_change(user)
