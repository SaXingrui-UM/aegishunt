"""Controlled model registry page."""

from __future__ import annotations

import streamlit as st

from aegishunt.frontend.client import AegisHuntApiClient, ApiClientError
from aegishunt.frontend.components import actor_input, api_error, page_header, table


def render(client: AegisHuntApiClient) -> None:
    page_header("Model Lab", "Verified bundles and explicit activation")
    try:
        models = client.models()
    except ApiClientError as error:
        api_error(error)
        return
    table(
        (
            {
                "model_id": item.model_id,
                "engine": item.engine,
                "version": item.version,
                "state": item.state,
                "active": item.active,
                "artifact": item.artifact_available,
            }
            for item in models.items
        ),
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
        item for item in models.items if item.artifact_available and item.engine != "fusion"
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
