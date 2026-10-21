from strands.models.bedrock import BedrockModel


def load_model() -> BedrockModel:
    """Get Bedrock model client using IAM credentials."""
    # Amazon Nova Pro via the APAC cross-region inference profile.
    # Low temperature keeps tool calls and code edits precise.
    return BedrockModel(
        model_id="apac.amazon.nova-pro-v1:0",
        temperature=0.2,
        max_tokens=8000,
    )
