<!--
Sync Impact Report:
Version: 0.0.0 → 1.0.0
Modified principles: Initial creation
Added sections: All core principles, Security Requirements, Documentation Standards, Governance
Removed sections: None
Templates requiring updates:
  ✅ .specify/templates/plan-template.md - Constitution Check section references updated
  ✅ .specify/templates/spec-template.md - Reviewed for alignment
  ✅ .specify/templates/tasks-template.md - Reviewed for alignment
Follow-up TODOs:
  - Create README.md after first feature implementation
  - Create CLAUDE.md when agent-specific guidance is needed
-->

# Will-Encrypt Constitution

## Core Principles

### I. Durable Trust Through Minimal Dependency
Every design decision MUST strengthen long-term security, user clarity, and resilience against both technical obsolescence and human error. The system MUST remain understandable, auditable, and operable with only open standards and transparent cryptographic primitives. No component may depend on a proprietary service or obscured process for its integrity.

**Rationale**: Encryption systems designed for long-term trust (wills, estates, generational data) must survive beyond current platforms, companies, and technologies. Dependencies on proprietary services create single points of failure that violate the principle of durable trust.

### II. Three Invariants (NON-NEGOTIABLE)
Every change MUST preserve these three invariants:
1. **No Single-Actor Decryption**: No single actor can decrypt alone
2. **Future-Generation Decryptability**: Future generations can decrypt with clear, documented procedures
3. **Provable Strength**: The encryption remains provably strong and independently verifiable

**Rationale**: These invariants define the core security model. Violating any one undermines the entire trust model of the system.

### III. Simplicity Over Convenience
Simplicity, reproducibility, and human readability take precedence over convenience or automation. Every component must be implementable from documentation alone, without requiring access to original tooling.

**Rationale**: Complex systems are harder to audit, verify, and maintain across decades. When convenience conflicts with clarity, clarity wins.

### IV. Test-First Development (NON-NEGOTIABLE)
TDD mandatory: Tests written → User approved → Tests fail → Implementation begins. The Red-Green-Refactor cycle is strictly enforced.

**Test requirements**:
- All cryptographic operations MUST have test vectors from independent sources
- All key ceremonies MUST be testable in isolation
- All multi-party protocols MUST have integration tests
- Edge cases (corrupted data, missing keys, protocol violations) MUST be tested

**Rationale**: Cryptographic software cannot be retrofitted with tests. Tests establish correctness before implementation bias sets in, and serve as executable specifications.

### V. Code Quality Standards
All code MUST meet these standards:
- **Readability**: Code is written for humans first, machines second
- **Documentation**: Every public interface documents assumptions, invariants, and failure modes
- **Error Handling**: All errors are explicit; no silent failures or default behaviors in cryptographic paths
- **Type Safety**: Use strongest type system features available; make illegal states unrepresentable
- **Minimal Coupling**: Each module has one responsibility and minimal knowledge of others

**Rationale**: Quality standards compound over time. Poor quality code becomes technical debt that blocks security audits and future maintenance.

## Security Requirements

### Cryptographic Standards
- MUST use only algorithms with public specifications and peer-reviewed security proofs
- MUST use established libraries (NaCl, libsodium, OpenSSL) over custom implementations
- MUST document threat model explicitly (what attacks are prevented, what is out of scope)
- MUST provide key rotation procedures
- MUST support algorithm agility (ability to migrate to new algorithms as old ones weaken)

### Key Management
- MUST implement key ceremony procedures (generation, distribution, storage, destruction)
- MUST support hardware security modules (HSMs) or secure enclaves where available
- MUST document key derivation paths and versioning
- MUST separate authentication keys from encryption keys
- MUST provide key recovery procedures (aligned with Invariant 2)

### Audit & Transparency
- MUST log all cryptographic operations (without leaking sensitive data)
- MUST provide verification tools for all encrypted artifacts
- MUST support third-party audits (code + procedures)
- MUST document security assumptions explicitly

## Documentation Standards

### Mandatory Documentation
Every feature MUST include:
- **README.md** (or section): What the feature does, why it exists, how to use it
- **CLAUDE.md** (or agent-specific file): Context for AI assistants performing maintenance
- **Threat Model**: What attacks are prevented, what is assumed secure
- **Key Ceremonies**: Step-by-step procedures for key operations
- **Disaster Recovery**: How to recover from key loss, corruption, compromise

### Living Documentation
- Documentation MUST be updated in the same commit as code changes
- Breaking changes MUST update all affected documentation before merge
- Examples MUST be tested (via doctest or equivalent)
- Diagrams SHOULD be generated from code or machine-readable specs (no stale architecture diagrams)

**Enforcement**: Pull requests that change behavior without updating documentation SHALL be rejected.

## Governance

### Amendment Process
1. Proposed changes MUST be documented in a pull request to this file
2. Version bump follows semantic versioning:
   - **MAJOR**: Backward-incompatible principle changes or removals
   - **MINOR**: New principles or materially expanded guidance
   - **PATCH**: Clarifications, wording improvements, non-semantic changes
3. All amendments MUST:
   - Update the Sync Impact Report at the top of this file
   - Review and update dependent templates (plan, spec, tasks)
   - Provide migration guidance if existing code is affected
4. Amendments require explicit approval before merge

### Compliance Review
- All pull requests MUST verify compliance with this constitution
- Complexity MUST be justified (document in plan.md Complexity Tracking section)
- Deviations require documented rationale and mitigation plan
- Security-critical changes require independent review

### Development Guidance
- Use CLAUDE.md (or agent-specific file) for runtime development guidance and context
- Use README.md for user-facing documentation and getting started
- When guidance conflicts, this constitution takes precedence
- Templates in `.specify/templates/` MUST align with constitutional principles

**Version**: 1.0.0 | **Ratified**: 2025-10-07 | **Last Amended**: 2025-10-07
