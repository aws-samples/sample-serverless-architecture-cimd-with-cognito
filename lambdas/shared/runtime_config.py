"""Runtime configuration for the Lambdas.

URLs are never Lambda environment variables (that would create the API -> Lambda -> API dependency cycle).
They are written to SSM by RegistrationStack after the final public URL exists and read here by static
parameter name, cached for SSM_CACHE_SECONDS. Environment variables override for local tests.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

_PARAM_KEYS = ("public_base_url", "origin_base_url", "authorization_server_url", "resource_url", "invoke_scope", "allowed_hosts")


@dataclass(frozen=True)
class Urls:
    public_base_url: str
    origin_base_url: str
    authorization_server_url: str
    resource_url: str
    invoke_scope: str
    allowed_hosts: tuple[str, ...]


_cache: tuple[float, Urls] | None = None


def _from_env() -> Urls | None:
    values = {k: os.environ.get(k.upper()) for k in _PARAM_KEYS}
    if all(values[k] for k in _PARAM_KEYS if k != "allowed_hosts"):
        return Urls(**{**values, "allowed_hosts": tuple(h for h in (values["allowed_hosts"] or "").split(",") if h)})  # type: ignore[arg-type]
    return None


def _from_ssm(prefix: str) -> Urls:
    import boto3  # runtime-provided

    client = boto3.client("ssm")
    params: dict[str, str] = {}
    token = None
    while True:
        kwargs = {"Path": prefix, "Recursive": False}
        if token:
            kwargs["NextToken"] = token
        resp = client.get_parameters_by_path(**kwargs)
        for p in resp["Parameters"]:
            params[p["Name"].rsplit("/", 1)[1]] = p["Value"]
        token = resp.get("NextToken")
        if not token:
            break
    missing = [k for k in _PARAM_KEYS if k not in params]
    if missing:
        raise RuntimeError(f"SSM parameters missing under {prefix}: {missing} (RegistrationStack not deployed?)")
    return Urls(
        public_base_url=params["public_base_url"],
        origin_base_url=params["origin_base_url"],
        authorization_server_url=params["authorization_server_url"],
        resource_url=params["resource_url"],
        invoke_scope=params["invoke_scope"],
        allowed_hosts=tuple(h for h in params["allowed_hosts"].split(",") if h),
    )


def get_urls(force: bool = False) -> Urls:
    global _cache
    env = _from_env()
    if env:
        return env
    ttl = int(os.environ.get("SSM_CACHE_SECONDS", "300"))
    now = time.time()
    if _cache and not force and now - _cache[0] < ttl:
        return _cache[1]
    urls = _from_ssm(os.environ["SSM_PREFIX"])
    _cache = (now, urls)
    return urls
