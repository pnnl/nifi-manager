from pydantic import TypeAdapter
from typing import List
from models import NifiUser
from config import Config, get_config
from utils import get, post, delete

CONFIG: Config = get_config()
URL = CONFIG.url + CONFIG.users_path


class UserNotCreated(Exception):
    pass


class UserExists(Exception):
    pass


class UserNotDeleted(Exception):
    pass


def get_all_users() -> List[NifiUser]:
    response = get(URL, CONFIG)
    try:
        status_code = response.status_code
        ta = TypeAdapter(List[NifiUser])
        if status_code == 200:
            return ta.validate_python(response.json().get("users", []))
        else:
            raise ValueError(f"response code not 200: {status_code}")

    except Exception:
        raise ValueError("something went wrong")


def get_user(user_id: str) -> NifiUser:
    response = get(URL + f"/{user_id}", CONFIG)
    status_code = response.status_code
    if status_code == 200:
        return NifiUser.model_validate_json(response.text)
    else:
        raise ValueError(
            f"could not get user {user_id}:\n\tresponse code not 200: {status_code}\n\tresponse: {response.text}"
        )


def create_user(identity: str) -> NifiUser:
    payload = {"revision": {"version": 0}, "component": {"identity": identity}}

    response = post(URL, CONFIG, payload)
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


def delete_user(user: NifiUser):
    response = delete(URL + f"/{user.id}?version={user.revision.version}", CONFIG)

    if response.status_code != 200:
        raise UserNotDeleted(
            f"could not delete user {user.id}: {response.text}, status_code: {response.status_code}"
        )
