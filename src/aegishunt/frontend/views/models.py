"""Latest-analysis model and fusion-policy presentation."""

from __future__ import annotations

from collections.abc import Sequence

import streamlit as st

from aegishunt.api.contracts import EffectiveModelState, ModelDescriptor
from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    page_header,
    section_header,
    table,
)


def _label(value: str) -> str:
    return value.replace("_", " ").title()


def _model_cards(
    client: AegisHuntApiClient,
) -> tuple[list[ModelDescriptor], EffectiveModelState]:
    effective = client.effective_models()
    return list(effective.operations.eligible_activation_models), effective


def _matching_supervised_bundle(
    models: Sequence[ModelDescriptor],
    effective: EffectiveModelState,
) -> ModelDescriptor | None:
    supervised = next(
        (
            item
            for item in effective.effective_models
            if item.engine_type == "supervised"
        ),
        None,
    )
    return next(
        (
            item
            for item in models
            if supervised is not None
            and item.engine == supervised.engine_type
            and item.version == supervised.version
            and item.checksum == supervised.artifact_hash
            and item.artifact_available
        ),
        None,
    )


def render(client: AegisHuntApiClient) -> None:
    page_header(
        "Model Lab",
        "Verified models and fusion policy used by the latest analysis",
    )
    try:
        models, effective = _model_cards(client)
    except ApiClientError as error:
        api_error(error)
        return

    if not effective.effective_models:
        st.info(effective.unavailable_reason or "No completed analysis is available yet.")
    else:
        columns = st.columns(len(effective.effective_models))
        for column, model in zip(columns, effective.effective_models, strict=True):
            with column:
                section_header(_label(model.engine_type))
                st.markdown(f"**{_label(model.algorithm or 'model')} · v{model.version}**")
                st.write(f"Validation status: **{_label(model.registry_status)}**")
                st.write(
                    f"Threshold: **{model.threshold:.1f}**"
                    if model.threshold is not None
                    else "Threshold: **Unavailable**"
                )
                st.caption(model.qualification)

    fusion = effective.effective_fusion_policy
    section_header("Fusion Policy")
    if fusion is None:
        st.info("No verified fusion policy is available for the latest analysis.")
    else:
        metrics = st.columns(3)
        metrics[0].metric("Supervised weight", f"{fusion.supervised_weight:.0%}")
        metrics[1].metric("Anomaly weight", f"{fusion.anomaly_weight:.0%}")
        metrics[2].metric("Threshold", f"{fusion.fusion_threshold:.1f}")
        st.caption(
            "Status: Controlled experiment evaluated · Recommendation: "
            f"{_label(fusion.recommendation)} · Effective for latest job: "
            f"{'Yes' if fusion.effective_for_latest_job else 'No'}"
        )
        st.info(
            "Fusion matched the supervised baseline on the known controlled groups, "
            "but did not establish superiority."
        )

    matching_bundle = _matching_supervised_bundle(models, effective)
    if matching_bundle is not None:
        section_header("Verified feature importance")
        importance_label = st.radio(
            "Importance method",
            ("Native", "Permutation"),
            horizontal=True,
            help=(
                "Native uses the fitted tree model's deterministic importance vector. "
                "Permutation uses repeated validation-partition shuffles."
            ),
        )
        try:
            importance = client.model_importance(
                matching_bundle.model_id,
                kind=importance_label.casefold(),
            )
        except ApiClientError as error:
            api_error(error)
        else:
            if importance.available and importance.importance is not None:
                table(
                    (
                        {
                            "Feature": item.feature_name,
                            "Mean importance": f"{item.mean:.4f}",
                            "Standard deviation": (
                                "N/A"
                                if item.standard_deviation is None
                                else f"{item.standard_deviation:.4f}"
                            ),
                        }
                        for item in importance.importance
                    ),
                    empty_message="No verified importance entries are available.",
                )
                if importance_label == "Native":
                    st.caption(
                        "Native tree importance is one deterministic model vector; "
                        "standard deviation is not applicable."
                    )
                else:
                    st.caption(
                        "Permutation importance uses the "
                        f"{importance.source_partition} partition · scoring "
                        f"{importance.scoring_metric} · {importance.repeats} repeats."
                    )
                st.caption("Feature importance is non-causal.")
            else:
                st.info(importance.message)

    with st.expander("Technical provenance", expanded=False):
        if not effective.global_active_models:
            st.write(
                "No global model pointer is active; the completed job used immutable "
                "runtime-pinned artifacts."
            )
        else:
            st.markdown("**Global active model pointers**")
            table(
                (
                    {
                        "Engine": item.engine,
                        "Version": item.version,
                        "Status": _label(item.state),
                        "Artifact hash": item.checksum,
                    }
                    for item in effective.global_active_models
                ),
                empty_message="No global model pointer is active.",
            )
        st.write(
            f"Latest runtime job: `{effective.latest_runtime_job_id}` · "
            f"snapshot: `{effective.snapshot_created_at}`"
        )
        table(
            (
                {
                    "Engine": item.engine_type,
                    "Artifact hash": item.artifact_hash,
                    "Feature schema": item.feature_schema_version,
                    "Source": item.source,
                }
                for item in effective.effective_models
            ),
            empty_message="No runtime-pinned model provenance is available.",
        )
        if fusion is not None:
            st.write(
                f"Fusion policy `{fusion.policy_id}` v{fusion.policy_version} · "
                f"evidence `{fusion.evaluation_source}` · hash `{fusion.artifact_hash}`"
            )
        if matching_bundle is None:
            st.caption(
                "Verified importance evidence matching the effective supervised model "
                "is not present in the global registry."
            )
        st.caption(effective.operations.training_message)
        st.caption(effective.operations.activation_message)

    if effective.operations.training_ready:
        with st.expander("Controlled training", expanded=False):
            with st.form("train-model"):
                engine = st.selectbox("Engine", ("supervised", "anomaly"))
                profiles = (
                    ("supervised-default", "supervised-corrective")
                    if engine == "supervised"
                    else ("anomaly-default", "anomaly-lof-candidate")
                )
                profile = st.selectbox("Allowlisted profile", profiles)
                new_version = st.text_input("Explicit new version")
                dataset = st.text_input("Approved dataset/candidate identity")
                actor = actor_input(key="train-actor")
                reason = st.text_area("Reason", key="train-reason")
                confirm = st.checkbox(
                    "Confirm controlled training; the model will not be activated",
                    key="train-confirm",
                )
                submitted = st.form_submit_button("Train verified candidate")
            if submitted and confirm:
                try:
                    trained = client.train_model(
                        engine=engine,
                        profile=profile,
                        new_version=new_version,
                        approved_dataset_identity=dataset,
                        actor=actor,
                        reason=reason,
                    )
                    st.success(
                        f"Model {trained.version} was created but was not auto-activated."
                    )
                except ApiClientError as error:
                    api_error(error)

    eligible = [
        item
        for item in models
        if item.model_id in effective.operations.eligible_activation_model_ids
        and item.activation_eligible
    ]
    if effective.operations.activation_ready and eligible:
        with st.expander("Activation", expanded=False):
            with st.form("activate-model"):
                model_id = st.selectbox(
                    "Verified model",
                    [item.model_id for item in eligible],
                )
                actor = actor_input(key="activate-actor")
                reason = st.text_area("Reason", key="activate-reason")
                expected = st.text_input("Expected current active version")
                confirm = st.checkbox("Confirm verified model activation")
                submitted = st.form_submit_button("Activate model")
            if submitted and confirm:
                try:
                    result = client.activate_model(
                        model_id,
                        actor=actor,
                        reason=reason,
                        expected_active_version=expected or None,
                    )
                    st.success(f"Active {result.engine} model: {result.version}")
                except ApiClientError as error:
                    api_error(error)
