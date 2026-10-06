#pragma once

#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace ai_tool_policy {

// Bound request identifiers before copying them into a decision record.
inline constexpr std::size_t max_identifier_length = 256;

enum class Decision {
    allow,
    deny,
    approval_required,
};

enum class Reason {
    authorized,
    approval_required,
    invalid_request,
    unknown_principal,
    unknown_tool,
    missing_capability,
};

struct ToolBinding {
    std::string name;
    std::string capability;
    bool requires_approval = false;
};

struct PrincipalGrant {
    std::string principal;
    std::set<std::string> capabilities;
};

// The caller identity must come from trusted host context, not model arguments.
// arguments_json is deliberately opaque: policy evaluation never parses it.
struct ToolRequest {
    std::string request_id;
    std::string principal;
    std::string tool;
    std::string arguments_json;
};

// Deliberately excludes arguments, which may contain secrets or attacker text.
struct DecisionRecord {
    std::string request_id;
    std::string principal;
    std::string tool;
    Decision decision = Decision::deny;
    Reason reason = Reason::invalid_request;
};

class Policy final {
public:
    Policy(std::vector<ToolBinding> tools, std::vector<PrincipalGrant> grants);

    [[nodiscard]] DecisionRecord evaluate(const ToolRequest& request) const;

private:
    struct Binding {
        std::string capability;
        bool requires_approval;
    };

    // Immutable after construction; safe to share for concurrent read-only checks.
    std::map<std::string, Binding, std::less<>> tools_;
    std::map<std::string, std::set<std::string>, std::less<>> grants_;
};

[[nodiscard]] std::string_view to_string(Decision decision) noexcept;
[[nodiscard]] std::string_view to_string(Reason reason) noexcept;

}  // namespace ai_tool_policy
