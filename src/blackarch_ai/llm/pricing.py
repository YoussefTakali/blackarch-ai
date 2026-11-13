"""Cost estimation. Unknown prices stay unknown (None) — never guessed."""

from __future__ import annotations

from blackarch_ai.config import Pricing


def estimate_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    overrides: dict[str, Pricing] | None = None,
) -> float | None:
    if overrides and model in overrides:
        p = overrides[model]
        return (prompt_tokens * p.input_per_mtok + completion_tokens * p.output_per_mtok) / 1e6
    try:
        import litellm

        info = litellm.model_cost.get(model) or litellm.model_cost.get(model.split("/", 1)[-1])
        if not info or "input_cost_per_token" not in info:
            return None
        return (
            prompt_tokens * float(info.get("input_cost_per_token") or 0)
            + completion_tokens * float(info.get("output_cost_per_token") or 0)
        )
    except Exception:
        return None


def has_price(model: str, overrides: dict[str, Pricing] | None = None) -> bool:
    return estimate_cost(model, 1, 1, overrides) is not None
