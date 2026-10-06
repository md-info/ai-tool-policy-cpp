# Threat model: AI tool authorization gate

## Purpose

This component makes a narrow authorization decision before an application dispatches a tool call requested by an AI model. The application supplies the caller identity from trusted host context. A policy maps tool names to capabilities and principals to granted capabilities. Unknown identities and tools fail closed. Sensitive tools return `approval_required`.

## Assets

- User and service data reachable through tools.
- Tool side effects, such as deleting files or changing remote state.
- Credentials and sensitive values included in tool arguments.
- Integrity of the host's principal identity and policy configuration.

## Trust boundaries

- The model request, including tool name and arguments, is untrusted input.
- The principal identifier must be established by the host, outside model-controlled arguments.
- The policy configuration and code that enforces the returned decision are trusted.
- Tool execution occurs beyond this library; callers must stop dispatch unless the decision is `allow`.
- `approval_required` is a handoff state, not proof that approval occurred. A separate trusted approval workflow must verify and bind approval to the exact principal, tool, arguments, and request before execution.

## Attacker goals and controls

| Attacker goal | Control in this prototype | Remaining dependency |
| --- | --- | --- |
| Invoke an unregistered tool | Unknown tools return `deny` | Correct tool registry in the host |
| Impersonate a principal through model arguments | The API receives principal separately from opaque arguments | Host must authenticate and bind principal correctly |
| Call a tool without its capability | Principal-to-capability check | Policy must be least-privilege and current |
| Self-approve a sensitive action with `approved: true` | Arguments are never consulted for approval; sensitive tool returns `approval_required` | Trusted approval service and exact-request binding |
| Leak argument secrets through audit records | Decision record has no arguments field | Caller must avoid logging arguments elsewhere |
| Exploit malformed input to widen access | Empty identity fields deny; policy duplicates and empty configuration values reject | Host request parsing and memory safety remain in caller scope |
| Amplify decision-record copying with oversized identifiers | Empty or over-256-byte request IDs, principal names, and tool names are rejected before any are copied | The host still needs total request-size limits, parsing safeguards, and memory safety |

## Non-goals and limitations

- This is not a sandbox, prompt-injection detector, authentication system, approval UI, or tool executor.
- It does not validate JSON syntax or tool-specific schemas; the arguments are opaque.
- It does not constrain filesystem paths, network destinations, subprocesses, or total request/argument resource use. It only bounds the identifier strings copied into a decision record.
- It does not make a decision based on argument values. If authorization depends on a resource identifier or amount, the host needs a typed, validated authorization context and object-level policy.
- It does not itself emit or persist audit events. The caller can serialize `DecisionRecord` without arguments.
- The prototype has not been compiled in this environment yet.

## Security invariant

Only a known principal with the capability bound to a known tool may receive `allow`, and only when that tool does not require approval. Model-provided arguments cannot change the principal's grants or satisfy the approval requirement.
