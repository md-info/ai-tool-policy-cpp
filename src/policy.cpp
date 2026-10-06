#include "ai_tool_policy/policy.hpp"

#include <stdexcept>
#include <utility>

namespace ai_tool_policy {
namespace {

void require_nonempty(std::string_view value, std::string_view field) {
    if (value.empty()) {
        throw std::invalid_argument(std::string(field) + " must not be empty");
    }
}

}  // namespace

Policy::Policy(std::vector<ToolBinding> tools, std::vector<PrincipalGrant> grants) {
    for (auto& tool : tools) {
        require_nonempty(tool.name, "tool name");
        require_nonempty(tool.capability, "tool capability");
        const auto [_, inserted] = tools_.emplace(
            std::move(tool.name), Binding{tool.capability, tool.requires_approval});
        if (!inserted) {
            throw std::invalid_argument("duplicate tool binding");
        }
    }

    for (auto& grant : grants) {
        require_nonempty(grant.principal, "principal");
        for (const auto& capability : grant.capabilities) {
            require_nonempty(capability, "granted capability");
        }
        const auto [_, inserted] = grants_.emplace(
            std::move(grant.principal), std::move(grant.capabilities));
        if (!inserted) {
            throw std::invalid_argument("duplicate principal grant");
        }
    }
}

DecisionRecord Policy::evaluate(const ToolRequest& request) const {
    DecisionRecord result;
    if (request.request_id.empty() || request.principal.empty() || request.tool.empty() ||
        request.request_id.size() > max_identifier_length ||
        request.principal.size() > max_identifier_length ||
        request.tool.size() > max_identifier_length) {
        return result;
    }

    result.request_id = request.request_id;
    result.principal = request.principal;
    result.tool = request.tool;

    const auto principal = grants_.find(request.principal);
    if (principal == grants_.end()) {
        result.reason = Reason::unknown_principal;
        return result;
    }

    const auto tool = tools_.find(request.tool);
    if (tool == tools_.end()) {
        result.reason = Reason::unknown_tool;
        return result;
    }

    if (!principal->second.contains(tool->second.capability)) {
        result.reason = Reason::missing_capability;
        return result;
    }

    if (tool->second.requires_approval) {
        result.decision = Decision::approval_required;
        result.reason = Reason::approval_required;
        return result;
    }

    result.decision = Decision::allow;
    result.reason = Reason::authorized;
    return result;
}

std::string_view to_string(Decision decision) noexcept {
    switch (decision) {
        case Decision::allow: return "allow";
        case Decision::deny: return "deny";
        case Decision::approval_required: return "approval_required";
    }
    return "deny";
}

std::string_view to_string(Reason reason) noexcept {
    switch (reason) {
        case Reason::authorized: return "authorized";
        case Reason::approval_required: return "approval_required";
        case Reason::invalid_request: return "invalid_request";
        case Reason::unknown_principal: return "unknown_principal";
        case Reason::unknown_tool: return "unknown_tool";
        case Reason::missing_capability: return "missing_capability";
    }
    return "invalid_request";
}

}  // namespace ai_tool_policy
