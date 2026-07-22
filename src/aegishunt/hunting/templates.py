"""Versioned deterministic hypothesis templates and cautious ATT&CK references."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from aegishunt.schemas import InvestigationQuery, PossibleMitreMapping


@dataclass(frozen=True, slots=True)
class HypothesisTemplate:
    template_id: str
    title: str
    category: str
    mapping: PossibleMitreMapping | None
    benign_alternatives: tuple[str, ...]
    query_objective: str
    query_template: str


def _mapping(technique_id: str, name: str, support: str) -> PossibleMitreMapping:
    return PossibleMitreMapping(
        technique_id=technique_id,
        technique_name=name,
        source_url=f"https://attack.mitre.org/techniques/{technique_id}/",
        support=support,
        limitation=(
            "The mapping is a possible behavioral analogy only; local evidence does not "
            "establish technique execution, actor identity, or attribution."
        ),
    )


TEMPLATES: dict[str, HypothesisTemplate] = {
    "possible_network_reconnaissance": HypothesisTemplate(
        "possible_network_reconnaissance",
        "Possible network reconnaissance",
        "reconnaissance-like network behavior",
        _mapping("T1046", "Network Service Discovery", "Source fan-out or scan-like evidence."),
        ("authorized vulnerability scanning", "asset discovery or monitoring"),
        "Review destination diversity and authorization context.",
        "SELECT event_time, source_ip, destination_ip, destination_port "
        "WHERE source_ip = :source_ip AND event_time BETWEEN :first_seen AND :last_seen",
    ),
    "possible_credential_abuse": HypothesisTemplate(
        "possible_credential_abuse",
        "Possible credential abuse",
        "credential-use anomaly",
        _mapping("T1078", "Valid Accounts", "Authentication-related correlated evidence."),
        ("legitimate user travel", "service-account or automation behavior"),
        "Review authentication outcomes and identity context.",
        "SELECT event_time, user, source_ip, outcome WHERE user = :user "
        "AND event_time BETWEEN :first_seen AND :last_seen",
    ),
    "possible_brute_force_activity": HypothesisTemplate(
        "possible_brute_force_activity",
        "Possible brute-force activity",
        "repeated authentication or connection failures",
        _mapping("T1110", "Brute Force", "Repeated failure-like reason evidence."),
        ("misconfigured client retries", "expired credentials or service outage"),
        "Review failure outcomes and attempt rate.",
        "SELECT event_time, source_ip, destination_ip, outcome "
        "WHERE source_ip = :source_ip AND event_time BETWEEN :first_seen AND :last_seen",
    ),
    "possible_beaconing_behavior": HypothesisTemplate(
        "possible_beaconing_behavior",
        "Possible beacon-like behavior",
        "regular network timing",
        _mapping("T1071", "Application Layer Protocol", "Regular timing in correlated alerts."),
        ("scheduled health checks", "periodic telemetry or software updates"),
        "Review timing regularity and destination ownership.",
        "SELECT event_time, source_ip, destination_ip WHERE source_ip = :source_ip "
        "AND destination_ip = :destination_ip "
        "AND event_time BETWEEN :first_seen AND :last_seen",
    ),
    "possible_command_and_control_pattern": HypothesisTemplate(
        "possible_command_and_control_pattern",
        "Possible command-and-control pattern",
        "periodic multi-engine suspicion",
        _mapping(
            "T1071",
            "Application Layer Protocol",
            "Periodic and multi-engine evidence overlap.",
        ),
        ("managed-agent heartbeat", "legitimate persistent application traffic"),
        "Review endpoint process and network timing evidence.",
        "SELECT event_time, host, process, destination_ip WHERE host = :host "
        "AND event_time BETWEEN :first_seen AND :last_seen",
    ),
    "possible_data_exfiltration_pattern": HypothesisTemplate(
        "possible_data_exfiltration_pattern",
        "Possible data-exfiltration pattern",
        "outbound transfer suspicion",
        _mapping("T1041", "Exfiltration Over C2 Channel", "Exfiltration-like reason evidence."),
        ("authorized backup or synchronization", "large legitimate application transfer"),
        "Review transfer volume, destination ownership, and business context.",
        "SELECT event_time, source_ip, destination_ip, bytes_out "
        "WHERE source_ip = :source_ip AND event_time BETWEEN :first_seen AND :last_seen",
    ),
    "possible_denial_of_service_behavior": HypothesisTemplate(
        "possible_denial_of_service_behavior",
        "Possible denial-of-service behavior",
        "many-source destination fan-in",
        _mapping("T1498", "Network Denial of Service", "Destination fan-in evidence."),
        ("flash crowd", "load test or distributed monitoring"),
        "Review service health and source diversity.",
        "SELECT event_time, source_ip, destination_ip, packets "
        "WHERE destination_ip = :destination_ip "
        "AND event_time BETWEEN :first_seen AND :last_seen",
    ),
    "unclassified_behavioral_anomaly": HypothesisTemplate(
        "unclassified_behavioral_anomaly",
        "Unclassified behavioral anomaly",
        "unclassified correlated suspicious behavior",
        None,
        ("unmodeled legitimate workload", "measurement or model error"),
        "Review the source alerts and establish local operational context.",
        "SELECT * FROM security_alerts WHERE alert_id IN (:supporting_alert_ids)",
    ),
}

TEMPLATE_CATALOG_VERSION: Literal["1.0.0"] = "1.0.0"
TEMPLATE_PRIORITY = (
    "possible_command_and_control_pattern",
    "possible_data_exfiltration_pattern",
    "possible_credential_abuse",
    "possible_brute_force_activity",
    "possible_network_reconnaissance",
    "possible_denial_of_service_behavior",
    "possible_beaconing_behavior",
    "unclassified_behavioral_anomaly",
)


def query_for(template: HypothesisTemplate) -> InvestigationQuery:
    return InvestigationQuery(
        data_source="local_security_telemetry",
        objective=template.query_objective,
        query_template=template.query_template,
        parameters={
            "source": "alert_group evidence",
            "first_seen": "alert_group.first_seen",
            "last_seen": "alert_group.last_seen",
        },
    )
