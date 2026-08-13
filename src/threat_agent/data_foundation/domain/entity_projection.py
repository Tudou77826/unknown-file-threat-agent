from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from ...contracts import EntityAlias, EntityIdentity, NormalizedActivity, ObservedRelation


RESOLVER_VERSION = "entity-resolver/1.0"


def _id(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:24]
    return f"entity-{kind}-{digest}"


def _relation_id(kind: str, source: str, target: str, activity_id: str) -> str:
    digest = hashlib.sha256(f"{kind}:{source}:{target}:{activity_id}".encode()).hexdigest()[:24]
    return f"relation-{digest}"


def _process_lifecycle(source_ref: str) -> str | None:
    value = source_ref.rsplit(":", 1)[-1]
    if value.isdigit() and len(value) >= 10:
        return datetime.fromtimestamp(int(value) / 1000, tz=timezone.utc).isoformat()
    return None


@dataclass(frozen=True)
class EntityProjection:
    entities: list[EntityIdentity]
    relations: list[ObservedRelation]


class DeterministicEntityProjector:
    """Build a reconstructable identity/relationship projection from observed activities."""

    def project(self, activity: NormalizedActivity) -> EntityProjection:
        entities: dict[str, EntityIdentity] = {}
        relations: list[ObservedRelation] = []

        def entity(kind: str, source_ref: str, *, lifecycle: str | None = None, **attributes):
            if kind == "process" and lifecycle is None:
                lifecycle = _process_lifecycle(source_ref)
            identity_key = f"{source_ref}:{lifecycle}" if lifecycle else source_ref
            entity_id = _id(kind, identity_key)
            entities[entity_id] = EntityIdentity(
                tenant_id=activity.tenant_id,
                source_identity=RESOLVER_VERSION,
                entity_id=entity_id,
                entity_type=kind,
                aliases=[EntityAlias(source_system=activity.source_system, source_id=source_ref)],
                valid_from=activity.observed_at if lifecycle else None,
                resolution_confidence=1.0 if lifecycle or kind != "process" else 0.6,
                attributes={key: value for key, value in attributes.items() if value is not None},
            )
            return entity_id

        def relation(kind: str, source: str, target: str, *, resolved: bool = True, reason: str | None = None):
            relations.append(ObservedRelation(
                tenant_id=activity.tenant_id,
                source_identity=RESOLVER_VERSION,
                relation_id=_relation_id(kind, source, target, activity.activity_id),
                relation_type=kind,
                source_entity_ref=source,
                target_entity_ref=target,
                valid_from=activity.observed_at,
                supporting_activity_refs=[activity.activity_id],
                resolution_status="resolved" if resolved else "candidate",
                confidence=1.0 if resolved else 0.6,
                ambiguity_reason=reason,
                resolver_version=RESOLVER_VERSION,
            ))

        host_ref = getattr(activity, "host_ref", None)
        host_id = entity("host", host_ref) if host_ref else None
        for ref in _activity_refs(activity):
            if ref.startswith("user:"):
                entity("user", ref)

        if activity.activity_type == "process":
            lifecycle = activity.process_started_at.isoformat() if activity.process_started_at else None
            process_id = entity(
                "process", activity.process_ref, lifecycle=lifecycle,
                host_ref=activity.host_ref, pid=activity.pid, started_at=lifecycle,
            )
            if host_id:
                relation("hosts", host_id, process_id, resolved=lifecycle is not None,
                         reason=None if lifecycle else "process start time is unavailable")
            if activity.parent_process_ref:
                parent_id = entity("process", activity.parent_process_ref)
                relation("parent_of", parent_id, process_id, resolved=lifecycle is not None,
                         reason=None if lifecycle else "child process lifecycle is incomplete")
            for target in activity.target_refs:
                file_id = entity("file", target)
                relation("executes", process_id, file_id)
        elif activity.activity_type == "file":
            file_id = entity("file", activity.file_ref, digest=activity.content_digest, path=activity.path)
            if activity.acting_process_ref:
                process_id = entity("process", activity.acting_process_ref)
                relation("acts_on", process_id, file_id, resolved=False,
                         reason="acting process reference has no verified lifecycle in this activity")
        elif activity.activity_type == "network":
            if activity.process_ref:
                process_id = entity("process", activity.process_ref)
                if activity.destination_endpoint_ref:
                    endpoint_id = entity("network_endpoint", activity.destination_endpoint_ref)
                    relation("connects_to", process_id, endpoint_id, resolved=False,
                             reason="process reference has no verified lifecycle in this activity")
            elif activity.destination_endpoint_ref:
                entity("network_endpoint", activity.destination_endpoint_ref)
        elif activity.activity_type == "socket":
            if activity.process_ref:
                process_id = entity("process", activity.process_ref)
                socket_id = entity("network_endpoint", activity.socket_ref)
                relation("uses_socket", process_id, socket_id, resolved=False,
                         reason="process reference has no verified lifecycle in this activity")
        elif activity.activity_type == "service":
            service_id = entity("service", activity.service_ref)
            if activity.executable_ref:
                file_id = entity("file", activity.executable_ref)
                relation("configured_to_execute", service_id, file_id)
        elif activity.activity_type == "package":
            package_id = entity("package", activity.package_ref)
            if activity.file_ref:
                file_id = entity("file", activity.file_ref)
                relation("owns", package_id, file_id)
        elif activity.activity_type == "asset":
            entity("business_asset", activity.asset_ref, **activity.attributes)

        return EntityProjection(list(entities.values()), relations)


def _activity_refs(activity: NormalizedActivity) -> set[str]:
    refs = set(activity.subject_refs) | set(activity.actor_refs) | set(activity.target_refs)
    for name in (
        "process_ref", "parent_process_ref", "source_endpoint_ref", "destination_endpoint_ref",
        "file_ref", "acting_process_ref", "service_ref", "executable_ref", "package_ref",
        "asset_ref",
    ):
        value = getattr(activity, name, None)
        if value:
            refs.add(str(value))
    return refs
