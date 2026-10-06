# AI Tool Policy Gate (C++20)

A small policy decision component for applications that let an AI model request tools. The host supplies the authenticated principal separately from model-controlled arguments. The policy maps each tool to a capability and each principal to its allowed capabilities. Unknown principals, tools, malformed requests, and missing capabilities are denied. Sensitive tools return `approval_required`.

Request IDs, principal names, and tool names are limited to 256 bytes. Oversized or empty identifiers are rejected before they are copied into the decision record.

The model's argument text is opaque to the policy engine. An argument such as `{"approved":true}` cannot approve a sensitive action. The returned decision record intentionally contains no arguments, which helps callers avoid copying secrets or attacker-controlled text into authorization logs.

## Build and test

Requires CMake 3.20+ and a C++20 compiler:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build --build-config Release --output-on-failure
```

## Example

```cpp
using namespace ai_tool_policy;

Policy policy(
    {{"search", "knowledge.read", false},
     {"delete_file", "files.delete", true}},
    {{"assistant", {"knowledge.read", "files.delete"}}});

const ToolRequest request{
    "req-17",                  // host-generated request identifier
    authenticated_principal,  // host-authenticated; never copied from model arguments
    model_selected_tool,
    model_arguments_json};

const auto record = policy.evaluate(request);
switch (record.decision) {
    case Decision::allow:
        // Dispatch only after this explicit allow.
        break;
    case Decision::deny:
        // Do not dispatch.
        break;
    case Decision::approval_required:
        // Start a separate trusted approval flow; do not treat model arguments as approval.
        break;
}
```

## Important boundary

This library decides; it does not execute tools, authenticate callers, validate argument schemas, or collect human approval. The host must enforce the decision before dispatch. A production approval flow must bind approval to the exact principal, tool, arguments, and request. See [THREAT_MODEL.md](THREAT_MODEL.md) for assets, attacker goals, trust boundaries, and limitations.

## Status

Prototype published for review. The seven test cases passed in GitHub Actions on Ubuntu, Windows, and macOS for commit `f25095113ead8a75737c3d3bdf8a04cc57c55c95`. The current 256-byte identifier-bound change has not yet been compiled or run through tests; the earlier CI result does not cover it. This is build/test evidence for the cited commit, not evidence of production integration or an external security review.

