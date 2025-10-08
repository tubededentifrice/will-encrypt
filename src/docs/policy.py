"""Policy document generation."""


def generate_policy_document() -> str:
    """Generate policy document text."""
    return """# Access Policy

## Recovery Eligibility

Emergency recovery is authorized when:
- Account owner is deceased (death certificate required)
- Account owner is incapacitated (medical certification required)
- Legal authorization is provided (court order, power of attorney)

## Key Holder Coordination

1. **Initial Contact**: Executor contacts all key holders
2. **Proof Requirements**: Death certificate or legal documentation
3. **Share Release**: Key holders independently verify legitimacy
4. **Recovery Execution**: Executor follows recovery guide with collected shares

## Key Holder Responsibilities

- Protect share custody (paper backup, password manager, or HSM)
- Verify recovery legitimacy before releasing share
- Do not share with other key holders (prevents collusion)
- Report lost shares immediately to executor

## Audit Trail

- Document all recovery attempts
- Log share collection (who, when, what verification)
- Record decrypted message access

## Customization

This is a template. Customize for your specific requirements:
- Add specific key holder names and contact information
- Define your proof requirements
- Specify recovery approval process
"""
