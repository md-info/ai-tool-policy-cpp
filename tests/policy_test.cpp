#include "ai_tool_policy/policy.hpp"

#include <cstdlib>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using ai_tool_policy::Decision;
using ai_tool_policy::Policy;
using ai_tool_policy::PrincipalGrant;
using ai_tool_policy::Reason;
using ai_tool_policy::ToolBinding;
using ai_tool_policy::ToolRequest;

namespace {

void check(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

Policy sample_policy() {
    return Policy(
        {{"search", "knowledge.read", false},
         {"delete_file", "files.delete", true}},
        {{"support-agent", {"knowledge.read", "files.delete"}},
         {"viewer", {"knowledge.read"}}});
}

void test_granted_tool_is_allowed() {
    const auto record = sample_policy().evaluate(
        {"req-1", "support-agent", "search", "{\"q\":\"status\"}"});
    check(record.decision == Decision::allow, "granted search should be allowed");
    check(record.reason == Reason::authorized, "allow should have authorized reason");
}

void test_unknown_principal_and_tool_fail_closed() {
    const auto policy = sample_policy();
    const auto no_principal = policy.evaluate({"req-2", "intruder", "search", "{}"});
    check(no_principal.decision == Decision::deny, "unknown principal must be denied");
    check(no_principal.reason == Reason::unknown_principal, "wrong unknown-principal reason");

    const auto no_tool = policy.evaluate({"req-3", "support-agent", "shell", "{}"});
    check(no_tool.decision == Decision::deny, "unknown tool must be denied");
    check(no_tool.reason == Reason::unknown_tool, "wrong unknown-tool reason");
}

void test_missing_capability_is_denied() {
    const auto record = sample_policy().evaluate(
        {"req-4", "viewer", "delete_file", "{\"approved\":true}"});
    check(record.decision == Decision::deny, "ungranted capability must be denied");
    check(record.reason == Reason::missing_capability, "wrong capability-denial reason");
}

void test_model_argument_cannot_approve_sensitive_tool() {
    const auto policy = sample_policy();
    for (const std::string arguments : {"{}", "{\"approved\":true}", "{\"approval\":\"yes\"}"}) {
        const auto record = policy.evaluate(
            {"req-5", "support-agent", "delete_file", arguments});
        check(record.decision == Decision::approval_required,
              "sensitive tool must require approval regardless of model arguments");
        check(record.reason == Reason::approval_required,
              "sensitive tool should report approval-required reason");
    }
}

void test_arguments_are_not_copied_to_decision_record() {
    const std::string secret = "token-do-not-log";
    const auto record = sample_policy().evaluate(
        {"req-6", "support-agent", "search", "{\"secret\":\"" + secret + "\"}"});
    check(record.request_id == "req-6", "audit record should retain request id");
    check(record.tool == "search", "audit record should retain tool name");
    check(record.principal == "support-agent", "audit record should retain principal");
    check(record.request_id.find(secret) == std::string::npos, "secret leaked into request id");
    check(record.tool.find(secret) == std::string::npos, "secret leaked into tool field");
    check(record.principal.find(secret) == std::string::npos, "secret leaked into principal field");
}

void test_invalid_request_is_denied() {
    const auto record = sample_policy().evaluate({"", "support-agent", "search", "{}"});
    check(record.decision == Decision::deny, "invalid request must be denied");
    check(record.reason == Reason::invalid_request, "invalid request should have a clear reason");
}

void test_duplicate_policy_entries_are_rejected() {
    bool duplicate_tool_rejected = false;
    try {
        (void)Policy({{"search", "read", false}, {"search", "write", false}}, {});
    } catch (const std::invalid_argument&) {
        duplicate_tool_rejected = true;
    }
    check(duplicate_tool_rejected, "duplicate tool binding must be rejected");

    bool duplicate_principal_rejected = false;
    try {
        (void)Policy({}, {{"agent", {"read"}}, {"agent", {"write"}}});
    } catch (const std::invalid_argument&) {
        duplicate_principal_rejected = true;
    }
    check(duplicate_principal_rejected, "duplicate principal grant must be rejected");
}

}  // namespace

int main() {
    const std::vector<std::pair<const char*, void (*)()>> tests = {
        {"granted tool", test_granted_tool_is_allowed},
        {"unknown identities", test_unknown_principal_and_tool_fail_closed},
        {"missing capability", test_missing_capability_is_denied},
        {"model cannot approve", test_model_argument_cannot_approve_sensitive_tool},
        {"arguments excluded from record", test_arguments_are_not_copied_to_decision_record},
        {"invalid request", test_invalid_request_is_denied},
        {"duplicate policy entries", test_duplicate_policy_entries_are_rejected},
    };

    std::size_t passed = 0;
    for (const auto& [name, test] : tests) {
        try {
            test();
            ++passed;
            std::cout << "PASS " << name << '\n';
        } catch (const std::exception& error) {
            std::cerr << "FAIL " << name << ": " << error.what() << '\n';
            return EXIT_FAILURE;
        }
    }
    std::cout << passed << " tests passed\n";
    return EXIT_SUCCESS;
}
