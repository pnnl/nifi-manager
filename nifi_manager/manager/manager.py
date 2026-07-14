import logging
from typing import Dict, FrozenSet, List, Tuple

from config import Config
from cryptography import x509
from cryptography.x509.oid import NameOID
from services.users import (
    sync_user,
    get_existing_users,
    del_non_acl_users,
)
from services.groups import (
    sync_group,
    get_existing_groups,
    del_non_acl_groups,
)
from services.policies import (
    sync_policy,
    get_existing_policies,
    del_non_acl_policies,
)
from services.process_groups import get_root_pg_id
from methods import health

from pathlib import Path
import json

from models import (
    ACLList,
    ExistingACL,
    NifiUser,
    NifiGroup,
    NifiPolicy,
    Policy,
    NifiResource,
    NifiMember,
    NifiMemberSet,
    Change,
)


class NoCurrentUser(Exception):
    pass


class UserNotExists(Exception):
    pass


class GroupNotExists(Exception):
    pass


class HealthcheckFailed(Exception):
    pass


class NifiManager:
    def __init__(self, config: Config, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.failures: List[Exception] = (
            []
        )  # keep a list of all failures to print out at the end
        self.changes: List[Change] = []

        self.current_username = self._get_current_username(
            Path(self.config.cert_path) / "tls.crt"
        )

        if self.config.dry_run:
            self.logger.info(f"running in DRY_RUN mode - no changes will be made")
        if self.config.prune:
            self.logger.warning(
                f"running with prune enabled - users, groups, and policies not in the acl will be deleted"
            )

    def run(self) -> Tuple[List[Change], List[Exception]]:
        self.logger.debug(f"running script as: {self.current_username}")
        self.healthcheck()

        self.root_pg_id = get_root_pg_id()
        self.logger.debug(f"found root process group id: {self.root_pg_id}")

        self.logger.debug(f"pulling existing users")
        self.users: Dict[str, NifiUser] = get_existing_users()
        self.logger.debug(f"found {len(self.users.keys())} existing users")

        self.logger.debug(f"pulling existing groups")
        self.groups: Dict[str, NifiGroup] = get_existing_groups()
        self.logger.debug(f"found {len(self.groups.keys())} existing groups")

        self.logger.debug(f"pulling existing policies")
        self.policies: Dict[str, NifiPolicy] = get_existing_policies(self.root_pg_id)
        self.logger.debug(f"found {len(self.policies.keys())} existing policies")
        self.logger.debug(f"building existing acl")
        self.existing_acl = self._get_existing_acl()

        try:
            self.current_user: NifiUser = self.users[self.current_username]
        except KeyError:
            raise NoCurrentUser(f"User {self.current_username} not found")
        self.cluster_users: FrozenSet[str] = self._get_cluster_users()
        self.logger.debug(
            f"found cluster users: {[user for user in self.cluster_users]}"
        )

        self.logger.debug(f"reading acl: {self.config.acl_file}")
        self.acl = self._read_acl_file(Path(self.config.acl_file))

        self.sync_users()
        self.sync_groups()
        self.sync_policies()

        return self.changes, self.failures

    def healthcheck(self) -> bool:
        try:
            return health(
                self.config.url + self.config.users_path,
                self.config.certs,
                self.config.verify,
                self.config.ca_cert_path,
            )
        except Exception as e:
            self.logger.error("healthcheck failed")
            raise HealthcheckFailed(e)

    @staticmethod
    def _get_current_username(cert_path: Path):
        """build the DN of the cert used to authenticate with the NIFI API"""
        # We use mTLS to authenticate with the NIFI API
        # The DN of our cert has to be added in NIFI as a user prior to using this script
        # So this user's permissions cannot be changed by this script to prevent crashes

        with cert_path.open("rb") as cert_file:
            cert = x509.load_pem_x509_certificate(cert_file.read())

        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        cn_value = common_names[0].value if common_names else None

        org_units = cert.subject.get_attributes_for_oid(
            NameOID.ORGANIZATIONAL_UNIT_NAME
        )
        ou_value = org_units[0].value if org_units else None

        return f"CN={cn_value}, OU={ou_value}"

    def _get_cluster_users(self) -> FrozenSet[str]:
        cluster_users = set()

        for user in self.users.keys():
            if "OU=NIFI" in user and user != self.current_username:
                cluster_users.add(user)

        return frozenset(cluster_users)

    @staticmethod
    def _resource_to_member(resource: NifiResource) -> NifiMember:
        return NifiMember(id=resource.id)

    def _get_user_list(self, policy: Policy) -> FrozenSet[NifiMember]:
        user_list = set(self._users_to_memberset(policy.users))
        # the following conditions ensure that the current user running this script will have the permissions needed to continue
        # this enforces the principle of least privilege and removes permissions from the "initial admin" that nifi sets that are now unnecessary

        # read on the flow
        if policy.resource == "flow":
            if policy.action == "read":
                user_list.add(self._resource_to_member(self.current_user))

        # read/write on tenants (users and groups)
        if policy.resource == "tenants":
            user_list.add(self._resource_to_member(self.current_user))

        # read/write on policies
        if policy.resource == "policies":
            user_list.add(self._resource_to_member(self.current_user))

        # write on proxy is needed for all cluster users
        if policy.resource == "proxy":
            for cluster_user in self.cluster_users:
                user_list.add(self._resource_to_member(self.users[cluster_user]))

        return NifiMemberSet.validate_python(user_list)

    def _read_acl_file(self, path: Path) -> ACLList:
        """reads the user provided acl list"""
        with path.open("r") as file:
            content = file.read()
            content = content.replace("{root_pg_id}", self.root_pg_id)
            acl_json = json.loads(content)

        return ACLList.model_validate_json(json.dumps(acl_json))

    def _get_existing_acl(self) -> ExistingACL:
        acl = {}

        acl["users"] = self.users
        acl["groups"] = self.groups
        acl["policies"] = self.policies

        return ExistingACL.model_validate(acl)

    def _users_to_memberset(
        self,
        users: FrozenSet[str],
    ) -> FrozenSet[NifiMember]:
        member_set = set()
        for user in users:
            try:
                member_set.add(self._resource_to_member(self.users[user]))
            except KeyError:
                if self.config.dry_run:
                    member_set.add(NifiMember(id=user))
                else:
                    raise UserNotExists(f"could not find {user} in user list")

        return frozenset(member_set)

    def _groups_to_memberset(
        self,
        groups: FrozenSet[str],
    ) -> FrozenSet[NifiMember]:
        member_set = set()
        for group in groups:
            try:
                member_set.add(self._resource_to_member(self.groups[group]))
            except KeyError:
                if self.config.dry_run:
                    member_set.add(NifiMember(id=group))
                else:
                    raise GroupNotExists(f"could not find {group} in group list")

        return frozenset(member_set)

    def sync_users(self):
        self.logger.debug(f"syncing users")
        synced_users = set()
        for user in self.acl.users:
            existing_user = self.existing_acl.users.get(user.identity, None)

            try:
                synced, change = sync_user(
                    user,
                    existing_user,
                    self.config.dry_run,
                )
                if synced:
                    self.users[user.identity] = synced
                    synced_users.add(user.identity)
                if change:
                    self.changes.append(change)

            except Exception as e:
                self.failures.append(e)

        to_delete = set(self.users.keys()) - synced_users

        if self.config.prune:
            changes, failures = del_non_acl_users(
                frozenset({self.users[username] for username in to_delete}),
                self.config.dry_run,
            )

            self.changes += changes
            self.failures += failures

    def sync_groups(self):
        self.logger.debug(f"syncing groups")
        synced_groups = set()
        for group in self.acl.groups:
            users = self._users_to_memberset(group.users)
            existing_group = self.existing_acl.groups.get(group.identity, None)

            try:
                synced, change = sync_group(
                    group,
                    existing_group,
                    users,
                    self.config.dry_run,
                )
                if synced:
                    self.groups[group.identity] = synced
                    synced_groups.add(group.identity)
                if change:
                    self.changes.append(change)

            except Exception as e:
                self.failures.append(e)

        to_delete = set(self.groups.keys()) - synced_groups

        if self.config.prune:
            changes, failures = del_non_acl_groups(
                frozenset({self.groups[groupname] for groupname in to_delete}),
                self.config.dry_run,
            )

            self.changes += changes
            self.failures += failures

    def sync_policies(self):
        self.logger.debug(f"syncing policies")
        synced_policies = set()
        for policy in self.acl.policies:
            user_list = self._get_user_list(policy)
            group_list = self._groups_to_memberset(policy.groups)
            permission = f"{policy.action}/{policy.resource}"

            try:
                synced, change = sync_policy(
                    policy,
                    self.existing_acl.policies.get(permission, None),
                    user_list,
                    group_list,
                    self.config.dry_run,
                )
                if synced:
                    self.policies[permission] = synced
                    synced_policies.add(permission)
                if change:
                    self.changes.append(change)

            except Exception as e:
                self.failures.append(e)

        to_delete = set(self.policies.keys()) - synced_policies

        if self.config.prune:
            changes, failures = del_non_acl_policies(
                frozenset({self.policies[permission] for permission in to_delete}),
                self.config.dry_run,
            )

            self.changes += changes
            self.failures += failures
