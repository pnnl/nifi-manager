from pydantic import TypeAdapter
from requests.exceptions import HTTPError
from typing import FrozenSet, List, Dict, Optional, Tuple
from models import (
    NifiPolicy,
    NifiMember,
    NifiMemberSet,
    Policy,
    PolicyChange,
)
from config import Config, get_config
from methods import get, post, put, delete
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


def normalize_resource(resource: str) -> str:
    return f"/{resource.strip().lstrip('/')}"


def get_permission(action: str, resource: str) -> str:
    return f"{action}{normalize_resource(resource)}"


def get_existing_policies(root_pg_id: str) -> Dict[str, NifiPolicy]:
    all_policies = _get_all_policies(root_pg_id)

    policies = {}
    for policy in all_policies:
        policies[f"{get_permission(policy.action, policy.resource)}"] = policy

    return policies


def sync_policy(
    policy: Policy,
    existing_policy: Optional[NifiPolicy],
    user_list: FrozenSet[NifiMember],
    group_list: FrozenSet[NifiMember],
    dry_run: bool,
) -> Tuple[Optional[NifiPolicy], Optional[PolicyChange]]:
    try:
        if existing_policy is None:
            change = PolicyChange(change="ADDED", policy=policy)
            if dry_run:
                logger.info(f"would create policy {policy.action} on {policy.resource}")
                return None, change
            created_policy = _create_policy(
                policy.action,
                policy.resource,
                user_list,
                group_list,
            )
            return created_policy, change

        existing_users = frozenset(
            {NifiMember(id=user.id) for user in existing_policy.users}
        )
        existing_groups = frozenset(
            {NifiMember(id=group.id) for group in existing_policy.user_groups}
        )

        if existing_users != user_list or existing_groups != group_list:
            change = PolicyChange(change="UPDATED", policy=policy)
            if dry_run:
                logger.info(f"would update policy {policy.action} on {policy.resource}")
                return existing_policy, change

            updated_policy = _update_policy(
                existing_policy,
                user_list,
                group_list,
            )
            return updated_policy, change

        return existing_policy, None
    except PolicyNotCreated as e:
        logger.warning(f"policy not created: {e}")
        raise
    except PolicyNotUpdated as e:
        logger.warning(f"policy not updated: {e}")
        raise
    except PolicyExists:
        logger.warning(
            f"policy {policy.action} on {policy.resource} already exists but we tried to create it..."
        )
        raise


def del_non_acl_policies(
    to_delete: FrozenSet[NifiPolicy], dry_run: bool
) -> Tuple[List[PolicyChange], List[Exception]]:
    changes: List[PolicyChange] = []
    failures: List[Exception] = []
    for policy in to_delete:
        try:
            if dry_run:
                logger.info(f"would delete policy {policy.action} on {policy.resource}")
                changes.append(_get_policy_removal_change(policy))
                continue

            logger.info(f"deleting policy: {policy.action} on {policy.resource}")
            change = _delete_policy(policy)
            changes.append(change)
        except Exception as e:
            logger.warning(e)
            failures.append(e)

    return changes, failures


def _get_policy_removal_change(policy: NifiPolicy) -> PolicyChange:
    return PolicyChange(
        change="REMOVED",
        policy=Policy(
            resource=policy.resource,
            action=policy.action,
            users=frozenset(),
            groups=frozenset(),
        ),
    )


def _get_all_policies(root_pg_id: str) -> FrozenSet[NifiPolicy]:
    policy_resources = [
        ("read", "/flow"),
        ("read", "/tenants"),
        ("write", "/tenants"),
        ("read", "/policies"),
        ("write", "/policies"),
        ("read", "/controller"),
        ("write", "/controller"),
        ("write", "/proxy"),
        ("write", "/restricted-components"),
        ("write", "/restricted-components/access-environment-credentials"),
        ("write", "/restricted-components/access-keytab"),
        ("write", "/restricted-components/access-ticket-cache"),
        ("write", "/restricted-components/execute-code"),
        ("write", "/restricted-components/export-nifi-details"),
        ("write", "/restricted-components/read-distributed-filesystem"),
        ("write", "/restricted-components/read-filesystem"),
        ("write", "/restricted-components/reference-remote-resources"),
        ("write", "/restricted-components/write-distributed-filesystem"),
        ("write", "/restricted-components/write-filesystem"),
        ("read", "/provenance"),
        ("read", "/site-to-site"),
        ("read", "/system"),
        ("read", "/counters"),
        ("write", "/counters"),
        ("read", f"/process-groups/{root_pg_id}"),
        ("write", f"/process-groups/{root_pg_id}"),
    ]

    policies = []
    for action, resource in policy_resources:
        try:
            policy = _get_policy(action, resource)
            policies.append(policy)
        except PolicyNotExists:
            logger.debug(f"no policy for {action} on {resource}")

    ta = TypeAdapter(FrozenSet[NifiPolicy])
    return ta.validate_python(policies)


def _get_policy(action: str, resource: str) -> NifiPolicy:
    try:
        response = get(
            URL + f"/{get_permission(action, resource)}",
            CONFIG.certs,
            CONFIG.verify,
            CONFIG.ca_cert_path,
        )

    except HTTPError as e:
        if e.response is not None:
            if e.response.status_code == 404:
                raise PolicyNotExists(f"policy not found") from e
        raise

    return NifiPolicy.model_validate_json(response.text)


def _create_policy(
    action: str,
    resource: str,
    users: FrozenSet[NifiMember],
    groups: FrozenSet[NifiMember],
) -> NifiPolicy:
    payload = {
        "revision": {"version": 0},
        "component": {
            "resource": f"{normalize_resource(resource)}",
            "action": action,
            "users": NifiMemberSet.dump_python(users, mode="json"),
            "userGroups": NifiMemberSet.dump_python(groups, mode="json"),
        },
    }
    try:
        response = post(URL, CONFIG.certs, CONFIG.verify, CONFIG.ca_cert_path, payload)

        return NifiPolicy.model_validate_json(response.text)
    except HTTPError as e:
        if e.response is not None:
            if e.response.status_code == 409:
                raise PolicyExists(
                    f"policy {action} on {resource} already exists and could not be created"
                ) from e
            raise PolicyNotCreated(
                f"policy {action} on {resource} could not be created: {e.response.text}, status_code: {e.response.status_code}"
            ) from e

        raise


def _update_policy(
    policy: NifiPolicy, users: FrozenSet[NifiMember], groups: FrozenSet[NifiMember]
) -> NifiPolicy:
    payload = {
        "revision": {"version": policy.revision.version},
        "component": {
            "id": policy.id,
            "resource": normalize_resource(policy.resource),
            "action": policy.action,
            "users": NifiMemberSet.dump_python(users, mode="json"),
            "userGroups": NifiMemberSet.dump_python(groups, mode="json"),
        },
    }

    try:
        response = put(
            URL + f"/{policy.id}",
            CONFIG.certs,
            CONFIG.verify,
            CONFIG.ca_cert_path,
            payload,
        )
        return NifiPolicy.model_validate_json(response.text)
    except HTTPError as e:
        if e.response is not None:
            if e.response.status_code == 404:
                raise PolicyNotExists(
                    f"policy {policy.action} on {policy.resource} does not exist"
                ) from e
            raise PolicyNotUpdated(
                f"policy {policy.action} on {policy.resource} could not be updated: {e.response.text}, status_code: {e.response.status_code}"
            ) from e
        raise


def _delete_policy(policy: NifiPolicy) -> PolicyChange:
    try:
        delete(
            URL + f"/{policy.id}?version={policy.revision.version}",
            CONFIG.certs,
            CONFIG.verify,
            CONFIG.ca_cert_path,
        )
    except HTTPError as e:
        if e.response is not None:
            if e.response.status_code == 404:
                raise PolicyNotExists(
                    f"could not delete policy as it doesn't exist"
                ) from e
            raise PolicyNotDeleted(
                f"could not delete policy {policy.id}: {e.response.text}, status_code: {e.response.status_code}"
            ) from e
        raise

    return _get_policy_removal_change(policy)
