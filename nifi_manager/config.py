from pydantic import Field, BeforeValidator, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Annotated, Literal, Tuple
from pathlib import Path

from functools import lru_cache

_log_levels = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "NOTSET"]
LogLevel = Annotated[
    _log_levels, BeforeValidator(lambda l: l.upper() if isinstance(l, str) else l)
]


class Config(BaseSettings):
    host: str = "localhost"
    port: int = 8443
    api_path: str = "nifi-api"
    users_path: str = "tenants/users"
    groups_path: str = "tenants/user-groups"
    policies_path: str = "policies"
    process_group_path: str = "flow/process-groups"
    acl_file: str = "acl.json"
    tls: bool = True
    cert_path: str = "/etc/nifi-certs"
    verify: bool = True

    log_level: LogLevel = "INFO"

    dry_run: bool = (
        Field(default=True, validation_alias="DRY_RUN")
        # this script deletes stuff, only take action when explicitly stated
    )
    prune: bool = Field(
        default=False, validation_alias="PRUNE"
    )  # this script can also manage all users, deleting users that were manually added

    @computed_field
    @property
    def certs(self) -> Tuple[str, str] | None:
        nifi_cert_path = Path(self.cert_path)
        if self.tls:
            return (str(nifi_cert_path / "tls.crt"), str(nifi_cert_path / "tls.key"))
        return None

    @computed_field
    @property
    def ca_cert_path(self) -> str:
        return str(Path(self.cert_path) / "ca.crt")

    @computed_field
    @property
    def url(self) -> str:
        return (
            f"http{'s' if self.tls else ''}://{self.host}:{self.port}/{self.api_path}/"
        )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="NIFI_MANAGER_",
        case_sensitive=False,
    )


@lru_cache()
def get_config() -> Config:
    return Config()
