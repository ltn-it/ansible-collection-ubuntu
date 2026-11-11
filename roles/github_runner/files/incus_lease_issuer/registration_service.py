"""Generate the pinned stock Linux service script after expected-ID registration.

This is the deterministic GenerateScripts step normally performed by stock
ConfigurationManager. It performs no registration, file write or service action.
The migration caller must still acquire its operating window, preserve the old
unit fence, publish and seal a fresh installation, reject unit collisions and
verify the actual generated unit before starting it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from . import registration
from .identity import require

# actions/runner d1eb12d4b115c301201de27d667284e1a80f2ab5,
# src/Misc/layoutbin/systemd.svc.sh.template, released in runner2.338.2.
TEMPLATE_SHA256 = "01a4cfda974c6b6de811c548788397e1f86f68696516f7a34b8dcfd086a4ddd3"


@dataclass(frozen=True)
class ServiceScript:
    service_name: str
    display_name: str
    content: bytes


def generate(template, target, settings):
    """Return stock script bytes only for the exact current Root-fenced target.

    This supports the organization's expected-ID-only registration path. It
    deliberately excludes repository registrations and stock's nondeterministic
    overlong-name truncation. The input settings must be read from the completed
    private registration journal by the Root migration caller, not job JSON.
    """
    registration._root()
    registration._fresh(target)
    require(registration.VERSION == "2.338.2", "registration-service-stock-version")
    require(type(template) is bytes and len(template) == 5151
            and hashlib.sha256(template).hexdigest() == TEMPLATE_SHA256,
            "registration-service-template")
    require(type(settings) is dict
            and {"agentId", "agentName", "poolId", "poolName", "serverUrl", "gitHubUrl",
                 "workFolder", "disableUpdate", "useV2Flow", "useRunnerAdminFlow"} <= set(settings)
            and set(settings) <= {"agentId", "agentName", "poolId", "poolName", "serverUrl", "gitHubUrl",
                                  "workFolder", "disableUpdate", "useV2Flow", "useRunnerAdminFlow", "serverUrlV2"},
            "registration-service-settings")
    expected = {"agentId": target.runner_id, "agentName": target.name, "poolId": target.group_id,
                "poolName": target.group_name, "gitHubUrl": "https://github.com/" + target.owner_login,
                "workFolder": target.work_folder}
    require(all(type(settings[key]) is type(value) and settings[key] == value for key, value in expected.items())
            and settings["disableUpdate"] is True
            and type(settings["useV2Flow"]) is bool and type(settings["useRunnerAdminFlow"]) is bool
            and (not settings["useRunnerAdminFlow"] or settings["useV2Flow"]),
            "registration-service-target-drift")
    registration._https_url(settings["serverUrl"])
    require(("serverUrlV2" in settings) is settings["useV2Flow"], "registration-service-flow-binding")
    if settings["useV2Flow"]:
        registration._https_url(settings["serverUrlV2"])
    # Stock RepoOrOrgName uses GitHubUrl's path for this hosted server suffix.
    # The validated org login/name use only stock's already-safe ASCII subset.
    service_name = "actions.runner." + target.owner_login + "." + target.name + ".service"
    require(len(service_name) <= 150, "registration-service-random-name-forbidden")
    display_name = "GitHub Actions Runner (" + target.owner_login + "." + target.name + ")"
    content = template.replace(b"{{SvcNameVar}}", service_name.encode("ascii"))
    content = content.replace(b"{{SvcDescription}}", display_name.encode("ascii"))
    require(b"{{SvcNameVar}}" not in content and b"{{SvcDescription}}" not in content,
            "registration-service-unexpanded-token")
    return ServiceScript(service_name, display_name, content)
