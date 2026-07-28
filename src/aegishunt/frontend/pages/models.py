"""Controlled model registry page."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import (
    actor_input,
    api_error,
    page_header,
    paginated_table,
    pagination_offset,
    table,
)


def render(client: AegisHuntApiClient) -> None:
    page_header("Model Lab", "Verified bundles and explicit activation")
    try:
        models = client.models(offset=pagination_offset("models-registry"))
        effective = client.effective_models()
    except ApiClientError as error:
        api_error(error)
        return
    paginated_table(
        models,
        (
            {
                "model_id": item.model_id,
                "engine": item.engine,
                "version": item.version,
                "state": item.state,
                "active": item.active,
                "artifact": item.artifact_available,
                "activation_eligible": item.activation_eligible,
                "activation_limitation": item.activation_ineligibility_reason,
            }
            for item in models.items
        ),
        key="models-registry",
        empty_message="No verified model bundles are available.",
    )
    st.info(
        "LOF remains validation-qualified and there is no untouched independent "
        "holdout. Training never runs on page load and never activates automatically."
    )
    st.warning(
        "Fusion recommendation remains inconclusive. Feature importance is non-causal, "
        "and missing verified importance evidence is shown as unavailable."
    )
    st.subheader("Global Active Models")
    active = [item for item in effective.global_active_models if item.active]
    table(
        (
            {
                "engine": item.engine,
                "version": item.version,
                "state": item.state,
                "artifact_hash": item.checksum,
                "source": "global_active",
            }
            for item in active
        ),
        empty_message="None. Runtime execution does not silently activate global pointers.",
    )
    st.subheader("Effective Models for Latest Demo/Runtime Job")
    table(
        (
            {
                "engine": item.engine_type,
                "algorithm": item.algorithm,
                "version": item.version,
                "registry_status": item.registry_status,
                "source": item.source,
                "runtime_job_id": str(item.runtime_job_id),
                "feature_schema": item.feature_schema_version,
                "artifact_hash": item.artifact_hash,
                "threshold": item.threshold,
                "global_pointer_active": item.global_pointer_active,
                "qualification": item.qualification,
                "limitations": "; ".join(item.limitations),
            }
            for item in effective.effective_models
        ),
        empty_message=effective.unavailable_reason
        or "No completed runtime job has an effective model snapshot.",
    )
    st.subheader("Fusion Policy")
    policies = [
        policy
        for policy in (
            effective.configured_fusion_policy,
            effective.effective_fusion_policy,
        )
        if policy is not None
    ]
    table(
        (
            {
                "source": policy.source,
                "policy_version": policy.policy_version,
                "status": policy.status,
                "artifact_source": policy.artifact_source,
                "artifact_hash": policy.artifact_hash,
                "supervised_weight": policy.supervised_weight,
                "anomaly_weight": policy.anomaly_weight,
                "rule_weight": policy.rule_weight,
                "context_weight": policy.context_weight,
                "fusion_threshold": policy.fusion_threshold,
                "feature_schema": policy.feature_schema_version,
                "evaluation_source": policy.evaluation_source,
                "recommendation": policy.recommendation,
                "configured_for_new_jobs": policy.configured_for_new_jobs,
                "effective_for_latest_job": policy.effective_for_latest_job,
                "limitations": "; ".join(policy.limitations),
            }
            for policy in policies
        ),
        empty_message=(
            "No verified configured or runtime-pinned fusion policy is available. "
            "This is an empty state, not an sklearn model row."
        ),
    )
    supervised = [item for item in models.items if item.engine == "supervised"]
    if supervised:
        selected = st.selectbox(
            "Global importance model",
            supervised,
            format_func=lambda item: f"{item.version} ({item.state})",
        )
        try:
            importance = client.model_importance(selected.model_id)
            if importance.available and importance.importance is not None:
                table(
                    (
                        {
                            "feature": item.feature_name,
                            "mean": item.mean,
                            "standard_deviation": item.standard_deviation,
                        }
                        for item in importance.importance
                    ),
                    empty_message="No importance entries are available.",
                )
            else:
                st.info(importance.message)
        except ApiClientError as error:
            api_error(error)
    train_tab, activate_tab = st.tabs(("Controlled training", "Activation"))
    with train_tab:
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
        item for item in models.items if item.activation_eligible
    ]
    if not eligible:
        return
    with activate_tab:
        with st.form("activate-model"):
            model_id = st.selectbox("Verified model", [item.model_id for item in eligible])
            actor = actor_input()
            reason = st.text_area("Reason")
            expected = st.text_input("Expected current active version (blank for none)")
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
