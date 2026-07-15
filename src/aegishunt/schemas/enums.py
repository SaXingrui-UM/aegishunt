"""Stable string enumerations used by schemas and database records."""

from enum import StrEnum


class SourceType(StrEnum):
    PCAP = "pcap"
    FLOW_CSV = "flow_csv"
    JSON_EVENT = "json_event"
    SAMPLE = "sample"
    LIVE_INTERFACE = "live_interface"


class IngestionMode(StrEnum):
    IMPORT = "import"
    REPLAY = "replay"
    LIVE = "live"


class LifecycleStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class NetworkProtocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class HypothesisStatus(StrEnum):
    PROPOSED = "proposed"
    UNDER_REVIEW = "under_review"
    REJECTED = "rejected"
    CONFIRMED = "confirmed"


class CaseStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CLOSED = "closed"


class CasePriority(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalystVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_EXPECTED = "benign_expected"
    NEEDS_MORE_INFORMATION = "needs_more_information"


class FeedbackObjectType(StrEnum):
    DETECTION = "detection"
    ALERT = "alert"
    ALERT_GROUP = "alert_group"
    HYPOTHESIS = "hypothesis"
    CASE = "case"


class ModelType(StrEnum):
    SUPERVISED = "supervised"
    ANOMALY = "anomaly"
    FUSION = "fusion"


class ModelStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    ACTIVE = "active"
    RETIRED = "retired"
    FAILED = "failed"
