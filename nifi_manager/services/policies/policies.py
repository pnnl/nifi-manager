from pydantic import TypeAdapter
from typing import FrozenSet
from models import NifiPolicy, NifiPolicy, NifiMember, NifiMemberSet
from config import Config, get_config
from utils import get, post, put, delete
import logging

logger = logging.getLogger("Policy Service")

CONFIG: Config = get_config()
URL = CONFIG.url + CONFIG.policies_path


class PolicyNotCreated(Exception):
    pass


class PolicyExists(Exception):
    pass


class PolicyNotExists(Exception):
    pass


class PolicyNotUpdated(Exception):
    pass


class PolicyNotDeleted(Exception):
    pass


def get_all_policies(root_pg_id: str) -> FrozenSet[NifiPolicy]:
    policy_resources = [
        "read/flow",
        "read/tenants",
        "write/tenants",
        "read/policies",
        "write/policies",
        "read/controller",
        "write/controller",
        "write/proxy",
        "write/restricted-components",
        "write/restricted-components/access-environment-credentials",
        "write/restricted-components/access-keytab",
        "write/restricted-components/access-ticket-cache",
        "write/restricted-components/execute-code",
        "write/restricted-components/export-nifi-details",
        "write/restricted-components/read-distributed-filesystem",
        "write/restricted-components/read-filesystem",
        "write/restricted-components/reference-remote-resources",
        "write/restricted-components/write-distributed-filesystem",
        "write/restricted-components/write-filesystem",
        "read/provenance",
        "read/site-to-site",
        "read/system",
        "read/counters",
        "write/counters",
        f"read/process-groups/{root_pg_id}",
        f"write/process-groups/{root_pg_id}",
    ]

    policies = []
    for policy_resource in policy_resources:
        split = policy_resource.split("/", maxsplit=1)
        action, resource = split[0], split[1]
        try:
            policy = get_policy(action, resource)
            policies.append(policy)
        except PolicyNotExists:
            logger.warning(f"no policy for {action} on {resource}")

    ta = TypeAdapter(FrozenSet[NifiPolicy])
    return ta.validate_python(policies)


def get_policy(action: str, resource: str) -> NifiPolicy:
    response = get(URL + f"/{action}/{resource}", CONFIG)

    status_code = response.status_code
    if status_code == 200:
        return NifiPolicy.model_validate_json(response.text)
    elif status_code == 404:
        raise PolicyNotExists(f"policy not found")
    else:
        raise ValueError(f"response code not 200: {status_code}")


def create_policy(
    action: str,
    resource: str,
    users: FrozenSet[NifiMember],
    groups: FrozenSet[NifiMember],
) -> NifiPolicy:
    payload = {
        "revision": {"version": 0},
        "component": {
            "resource": f"/{resource}",
            "action": action,
            "users": NifiMemberSet.dump_python(users, mode="json"),
            "userGroups": NifiMemberSet.dump_python(groups, mode="json"),
        },
    }
    response = post(URL, CONFIG, payload)

    if response.status_code in (200, 201):
        policy = NifiPolicy.model_validate_json(response.text)
        if not policy:
            raise PolicyNotCreated(
                f"policy {action} on {resource} could not be created: {response.text}, status_code: {response.status_code}"
            )
        return policy
    elif response.status_code == 409:
        raise PolicyExists(
            f"policy {action} on {resource} already exists and could not be created"
        )
    raise PolicyNotCreated(
        f"policy {action} on {resource} could not be created: {response.text}, status_code: {response.status_code}"
    )


def update_policy(
    policy: NifiPolicy, users: FrozenSet[NifiMember], groups: FrozenSet[NifiMember]
) -> str:
    payload = {
        "revision": {"version": policy.revision.version},
        "component": {
            "id": policy.id,
            "resource": policy.resource,
            "action": policy.action,
            "users": NifiMemberSet.dump_python(users, mode="json"),
            "userGroups": NifiMemberSet.dump_python(groups, mode="json"),
        },
    }

    response = put(URL + f"/{policy.id}", CONFIG, payload)
    if response.status_code in (200, 201):
        return response.json().get("id", "")
    elif response.status_code == 404:
        raise PolicyNotExists(
            f"policy {policy.action} on {policy.resource} does not exist"
        )
    raise PolicyNotUpdated(
        f"policy {policy.action} on {policy.resource} could not be updated: {response.text}, status_code: {response.status_code}"
    )


def delete_policy(policy: NifiPolicy):
    response = delete(URL + f"/{policy.id}?version={policy.revision.version}", CONFIG)

    if response.status_code != 200:
        raise PolicyNotDeleted(f"could not delete policy {policy.id}")
