"""Phase 13 regressions for integrity and scaling controls."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from aegishunt.config import DatasetSettings, FlowSettings
from aegishunt.datasets.errors import DatasetQualityError
from aegishunt.datasets.io import write_canonical_jsonl
from aegishunt.datasets.quality import analyze_quality
from aegishunt.datasets.schemas import CanonicalDatasetRow
from aegishunt.datasets.service import DatasetService
from aegishunt.flows.aggregator import FlowAggregator
from aegishunt.flows.packets import PacketRecord
from aegishunt.flows.registry import feature_names
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.fusion.dataset import build_controlled_experiment_dataset
from aegishunt.ml.fusion.engines import fit_experimental_engines
from aegishunt.ml.fusion.errors import FusionContractError
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.schemas.enums import NetworkProtocol
from tests.fixtures.anomaly import LOF_CANDIDATE_CONFIG_PATH
from tests.fixtures.datasets import LABEL_ROOT, REGISTRY_PATH, demo_rows
from tests.fixtures.fusion import fusion_config
from tests.fixtures.packets import at
from tests.fixtures.supervised import CORRECTIVE_CONFIG_PATH


def _replace_feature(
    row: CanonicalDatasetRow,
    *,
    record_id: str,
    feature_name: str,
    value: float,
) -> CanonicalDatasetRow:
    payload = row.model_dump(mode="python")
    payload["metadata"]["record_id"] = record_id
    values = list(row.features.values)
    values[feature_names().index(feature_name)] = value
    payload["features"]["values"] = values
    return CanonicalDatasetRow.model_validate(payload)


def _packet(index: int) -> PacketRecord:
    return PacketRecord(
        timestamp=at(index / 1_000),
        ip_version=4,
        source_ip=f"192.0.2.{index // 250 + 1}",
        destination_ip="198.51.100.1",
        source_port=10_000 + index,
        destination_port=443,
        protocol=NetworkProtocol.TCP,
        protocol_number=6,
        network_bytes=60,
        tcp_flags=0x02,
    )


def test_near_duplicate_detection_covers_quantization_boundaries() -> None:
    original = demo_rows()[0]
    left = _replace_feature(
        original,
        record_id="boundary-left",
        feature_name="bytes_per_second",
        value=100.49,
    )
    right = _replace_feature(
        original,
        record_id="boundary-right",
        feature_name="bytes_per_second",
        value=100.51,
    )

    report = analyze_quality((left, right), near_duplicate_tolerance=1.0)

    assert report.near_duplicate_count == 1
    assert report.near_duplicate_groups == (original.metadata.group_id,)


def test_flow_deadline_index_avoids_per_packet_full_table_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    aggregator = FlowAggregator(
        FlowSettings(
            idle_timeout_seconds=60,
            active_timeout_seconds=300,
            max_active_flows=1_000,
        ),
        source_id=UUID("00000000-0000-0000-0000-000000000001"),
        capture_session_id="phase13-deadline-index",
    )
    calls = 0
    original = aggregator._timeout_reason

    def counted(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(aggregator, "_timeout_reason", counted)
    for index in range(500):
        aggregator.process(_packet(index))

    assert aggregator.active_count == 500
    assert calls == 0
    assert aggregator.flush_capture_end()


def test_fusion_refit_rejects_unverified_model_and_schema_identities() -> None:
    config = fusion_config(supervised_model_id="aegishunt-supervised-unverified")
    mapper_path = LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml"
    from aegishunt.datasets.labels import LabelMapper

    dataset = build_controlled_experiment_dataset(config, LabelMapper.load(mapper_path))

    with pytest.raises(FusionContractError, match="identity"):
        fit_experimental_engines(
            dataset.stage("early"),
            dataset.stage("middle"),
            fusion_config=config,
            supervised_config=SupervisedTrainingConfig.load(CORRECTIVE_CONFIG_PATH),
            anomaly_config=AnomalyTrainingConfig.load(LOF_CANDIDATE_CONFIG_PATH),
        )


def test_controlled_demo_resplit_rejects_reissued_arbitrary_canonical_rows(
    tmp_path: Path,
) -> None:
    settings = DatasetSettings(
        registry_path=REGISTRY_PATH,
        label_mapping_root=LABEL_ROOT,
        raw_root=tmp_path / "raw",
        interim_root=tmp_path / "interim",
        processed_root=tmp_path / "processed",
        reports_root=tmp_path / "reports",
        demo_seed=4_204,
    )
    service = DatasetService(settings)
    rows = list(demo_rows())
    payload = rows[0].model_dump(mode="python")
    payload["features"]["values"] = list(rows[1].features.values)
    rows[0] = CanonicalDatasetRow.model_validate(payload)
    canonical = tmp_path / "substituted.jsonl"
    write_canonical_jsonl(rows, canonical)

    with pytest.raises(DatasetQualityError, match="provenance"):
        service.split_existing(
            canonical,
            data_root=tmp_path / "output" / "data",
            report_root=tmp_path / "output" / "reports",
        )
    assert not (tmp_path / "output").exists()
