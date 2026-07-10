import logging
from typing import Dict, FrozenSet, List, Tuple

from config import get_config, Config
from cryptography import x509
from cryptography.x509.oid import NameOID
from services.users import (
    get_all_users,
    create_user,
    delete_user,
    UserNotCreated,
    UserExists,
    UserNotDeleted,
)
from services.groups import (
    get_all_groups,
    create_group,
    update_group,
    delete_group,
    GroupNotCreated,
    GroupExists,
    GroupNotDeleted,
    GroupNotUpdated,
)
from services.policies import (
    get_all_policies,
    create_policy,
    update_policy,
    delete_policy,
    PolicyNotCreated,
    PolicyExists,
    PolicyNotDeleted,
    PolicyNotUpdated,
)
from services.process_groups import get_root_pg_id
from pathlib import Path
import json

from models import (
    ACLList,
    ExistingACL,
    NifiUser,
    NifiGroup,
    NifiPolicy,
    User,
    Group,
    Policy,
    NifiResource,
    NifiMember,
    NifiMemberSet,
    Change,
    UserChange,
    GroupChange,
    PolicyChange,
)


class NoCurrentUser(Exception):
    pass


class NifiUserManager:
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

        self.root_pg_id = get_root_pg_id()
        self.logger.debug(f"found root process group id: {self.root_pg_id}")

        self.logger.debug(f"pulling existing users")
        self.users: Dict[str, NifiUser] = self._get_existing_users()
        self.logger.debug(f"found {len(self.users.keys())} existing users")

        self.logger.debug(f"pulling existing groups")
        self.groups: Dict[str, NifiGroup] = self._get_existing_groups()
        self.logger.debug(f"found {len(self.groups.keys())} existing groups")

        self.logger.debug(f"pulling existing policies")
        self.policies: Dict[str, NifiPolicy] = self._get_existing_policies(
            self.root_pg_id
        )
        self.logger.debug(f"found {len(self.policies.keys())} existing policies")
        self.logger.debug(f"building existing acl")
        self.existing_acl = self._get_existing_acl()

        try:
            self.current_user: NifiUser = self.users[self.current_username]
        except KeyError:
            raise NoCurrentUser(f"User {self.current_username}")
        self.cluster_users: FrozenSet[str] = self._get_cluster_users()
        self.logger.debug(
            f"found cluster users: {[user for user in self.cluster_users]}"
        )

        self.logger.debug(f"reading acl: {self.config.acl_file}")
        self.acl = self._read_acl_file(Path(self.config.acl_file))

        self.logger.debug(f"syncing users")
        non_acl_users = self.sync_users()
        self.logger.debug(f"syncing groups")
        non_acl_groups = self.sync_groups()
        self.logger.debug(f"syncing policies")
        non_acl_polices = self.sync_policies()

        if self.config.prune:
            self.del_non_acl_users(non_acl_users)
            self.del_non_acl_groups(non_acl_groups)
            self.del_non_acl_policies(non_acl_polices)

        return self.changes, self.failures

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
        user_list = {
            self._resource_to_member(self.users[user]) for user in policy.users
        }

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

    @staticmethod
    def _get_existing_users() -> Dict[str, NifiUser]:
        all_users = get_all_users()

        users = {}
        for user in all_users:
            users[user.identity] = user

        return users

    @staticmethod
    def _get_existing_groups() -> Dict[str, NifiGroup]:
        all_groups = get_all_groups()

        groups = {}
        for group in all_groups:
            groups[group.identity] = group

        return groups

    @staticmethod
    def _get_existing_policies(root_pg_id: str) -> Dict[str, NifiPolicy]:
        all_policies = get_all_policies(root_pg_id)

        policies = {}
        for policy in all_policies:
            policies[f"{policy.action}{policy.resource}"] = policy

        return policies

    def _get_existing_acl(self) -> ExistingACL:
        acl = {}

        acl["users"] = self.users
        acl["groups"] = self.groups
        acl["policies"] = self.policies

        return ExistingACL.model_validate(acl)

    def sync_users(self) -> FrozenSet[str]:
        created_users = set()
        for user in self.acl.users:
            try:
                created_users.add(user.identity)
                if user.identity not in self.existing_acl.users:
                    if self.config.dry_run:
                        self.logger.info(f"would create user {user.identity}")
                        continue
                    created_user = create_user(user.identity)
                    self.users[user.identity] = created_user
                    self.changes.append(UserChange(change="ADDED", user=user))

            except UserNotCreated as e:
                self.logger.warning(f"could not create user: {e}")
                self.failures.append(e)
            except UserExists:
                self.logger.warning(
                    f"user {user.identity} already exists but we tried to create it..."
                )

        existing_users = set(self.users.keys())

        to_delete = (
            existing_users
            - created_users
            - {self.current_user.identity}
            - self.cluster_users
        )

        return frozenset(to_delete)

    def del_non_acl_users(self, to_delete: FrozenSet[str]) -> None:
        self.logger.info(f"users to be deleted: {[username for username in to_delete]}")
        for username in to_delete:
            try:
                if self.config.dry_run:
                    self.logger.info(f"would delete user {username}")
                    continue

                self.logger.info(f"deleting user: {username}...")
                delete_user(self.users[username])
                self.changes.append(
                    UserChange(change="REMOVED", user=User(identity=username))
                )
            except UserNotDeleted as e:
                self.logger.warning(e)
                self.failures.append(e)

    def sync_groups(self) -> FrozenSet[str]:
        created_groups = set()
        for group in self.acl.groups:
            try:
                created_groups.add(group.identity)
                users = NifiMemberSet.validate_python(
                    {self._resource_to_member(self.users[user]) for user in group.users}
                )
                existing_group = self.existing_acl.groups.get(group.identity, None)

                if not existing_group:
                    if self.config.dry_run:
                        self.logger.info(f"would create group {group.identity}")
                        continue

                    created_group = create_group(group.identity, users)
                    self.groups[group.identity] = created_group
                    self.changes.append(GroupChange(change="ADDED", group=group))
                    continue

                existing_users = frozenset(
                    {NifiMember(id=user.id) for user in existing_group.users}
                )
                if set(existing_users) != set(users):
                    if self.config.dry_run:
                        self.logger.info(f"would update group {group.identity}")
                        continue

                    update_group(self.existing_acl.groups[group.identity], users)
                    self.changes.append(GroupChange(change="UPDATED", group=group))
            except GroupNotCreated as e:
                self.logger.warning(f"group not created: {e}")
                self.failures.append(e)
            except GroupNotUpdated as e:
                self.logger.warning(f"group not updated: {e}")
                self.failures.append(e)
            except GroupExists:
                self.logger.warning(
                    f"group {group.identity} already exists but we tried to create it..."
                )

        existing_groups = set(self.groups.keys())

        to_delete = existing_groups - created_groups

        return frozenset(to_delete)

    def del_non_acl_groups(self, to_delete: FrozenSet[str]) -> None:
        self.logger.info(
            f"groups to be deleted: {[groupname for groupname in to_delete]}"
        )
        for groupname in to_delete:
            try:
                if self.config.dry_run:
                    self.logger.info(f"would delete group {groupname}")
                    continue

                self.logger.info(f"deleting group: {groupname}")
                delete_group(self.groups[groupname])
                self.changes.append(
                    GroupChange(
                        change="REMOVED",
                        group=Group(identity=groupname, users=frozenset()),
                    )
                )
            except GroupNotDeleted as e:
                self.logger.warning(e)
                self.failures.append(e)

    def sync_policies(self) -> FrozenSet[str]:
        created_policies = set()
        for policy in self.acl.policies:
            user_list = self._get_user_list(policy)
            group_list = frozenset(
                {
                    self._resource_to_member(self.groups[group])
                    for group in policy.groups
                }
            )

            try:
                permission = f"{policy.action}/{policy.resource}"
                existing_policy = self.existing_acl.policies.get(permission, None)
                created_policies.add(permission)
                if not existing_policy:
                    if self.config.dry_run:
                        self.logger.info(
                            f"would create policy {policy.action} on {policy.resource}"
                        )
                        continue
                    created_policy = create_policy(
                        policy.action,
                        policy.resource,
                        user_list,
                        group_list,
                    )
                    self.policies[permission] = created_policy
                    self.changes.append(PolicyChange(change="ADDED", policy=policy))
                    continue

                existing_users = frozenset(
                    {NifiMember(id=user.id) for user in existing_policy.users}
                )
                existing_groups = frozenset(
                    {NifiMember(id=group.id) for group in existing_policy.user_groups}
                )
                if existing_users != user_list or existing_groups != group_list:
                    if self.config.dry_run:
                        self.logger.info(
                            f"would update policy {policy.action} on {policy.resource}"
                        )
                        continue

                    update_policy(
                        self.existing_acl.policies[permission],
                        user_list,
                        group_list,
                    )
                    self.changes.append(PolicyChange(change="UPDATED", policy=policy))
            except PolicyNotCreated as e:
                self.logger.warning(f"policy not created: {e}")
                self.failures.append(e)
            except PolicyNotUpdated as e:
                self.logger.warning(f"policy not updated: {e}")
                self.failures.append(e)
            except PolicyExists:
                self.logger.warning(
                    f"policy {policy.action} on {policy.resource} already exists but we tried to create it..."
                )

        to_delete = set(self.policies.keys()) - created_policies

        return frozenset(to_delete)

    def del_non_acl_policies(self, to_delete: FrozenSet[str]) -> None:
        self.logger.info(f"policies to delete: {[policy for policy in to_delete]}")
        for policy in to_delete:
            try:
                if self.config.dry_run:
                    self.logger.info(f"would delete policy {policy}")
                    continue

                self.logger.info(f"deleting policy: {policy}")
                delete_policy(self.policies[policy])
                action, resource = policy.split("/", maxsplit=1)
                self.changes.append(
                    PolicyChange(
                        change="REMOVED",
                        policy=Policy(
                            action=action,
                            resource=resource,
                            users=frozenset(),
                            groups=frozenset(),
                        ),
                    )
                )
            except PolicyNotDeleted as e:
                self.logger.warning(e)
                self.failures.append(e)


if __name__ == "__main__":
    config = get_config()
    logging.basicConfig(
        level=config.log_level,
        format=f"%(asctime)s - %(name)-17s - %(levelname)-8s - {"DRY_RUN - " if config.dry_run else ""}%(message)s",
    )
    logger = logging.getLogger("Nifi User Manager")
    logging.getLogger("urllib3").setLevel(
        logging.WARNING
    )  # urllib3 debug logging is too noisy

    nifi_user_manager = NifiUserManager(config, logger)

    changes, failures = nifi_user_manager.run()
    if len(failures) != 0:
        logger.info(f"some errors occured: ")
        for error in failures:
            logger.error(error)
    else:
        logger.info(f"successfully synced nifi acl")
        if len(changes) != 0:
            logger.info("changes: ")
            for change in changes:
                logger.info(f"\t  {change}")
        else:
            logger.info("no changes were made")
