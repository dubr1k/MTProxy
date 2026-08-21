from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=32)

    @field_validator("username")
    @classmethod
    def valid(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError("invalid username")
        return value


class UserLimits(BaseModel):
    data_quota_bytes: int | None = Field(default=None, strict=True, ge=1, le=2**63 - 1)
    rate_limit_up_bps: int | None = Field(default=None, strict=True, ge=1, le=10**12)
    rate_limit_down_bps: int | None = Field(default=None, strict=True, ge=1, le=10**12)
    max_tcp_conns: int | None = Field(default=None, strict=True, ge=1, le=100_000)
    max_unique_ips: int | None = Field(default=None, strict=True, ge=1, le=100_000)
    expiration_rfc3339: str | None = Field(default=None, max_length=64)

    @field_validator("expiration_rfc3339")
    @classmethod
    def valid_expiration(cls, value):
        if value is None:
            return value
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid RFC3339 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("timezone is required")
        return value


class NaiveUserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    quota_bytes: int | None = Field(default=None, strict=True, ge=1, le=2**63 - 1)


class NaiveQuotaUpdate(BaseModel):
    quota_bytes: int | None = Field(default=None, strict=True, ge=1, le=2**63 - 1)


class MieruQuota(BaseModel):
    days: int = Field(strict=True, ge=1, le=3650)
    megabytes: int = Field(strict=True, ge=1, le=2**31 - 1)


class MieruUserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    quotas: list[MieruQuota] = Field(default_factory=list, max_length=16)
    expected_revision: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    allow_private_ip: bool = False
    allow_loopback_ip: bool = False

    @field_validator("username")
    @classmethod
    def username_bytes(cls, value):
        if len(value.encode()) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError("invalid username")
        return value


class MieruRevision(BaseModel):
    expected_revision: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")


class MieruQuotaUpdate(MieruRevision):
    quotas: list[MieruQuota] = Field(max_length=16)


class AdminCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["owner", "admin", "viewer"]


class AdminUpdate(BaseModel):
    role: Literal["owner", "admin", "viewer"] | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    active: bool | None = None


class VersionUpdate(BaseModel):
    version: str = Field(
        strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$"
    )
    expected_current: str | None = Field(
        default=None, strict=True, pattern=r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,63}$"
    )


class FleetNodeCreate(BaseModel):
    node_id: str = Field(pattern=r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")
    display_name: str = Field(min_length=1, max_length=128)
    inventory: dict = Field(default_factory=dict)


class FleetCommandCreate(BaseModel):
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
    operation: Literal[
        "telemt.inventory.refresh",
        "telemt.user.enable",
        "telemt.user.disable",
        "telemt.user.update_limits",
        "telemt.user.reset_quota",
    ]
    expected_telemt_revision: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    payload: dict
