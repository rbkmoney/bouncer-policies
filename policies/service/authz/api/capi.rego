package service.authz.api.capi

import data.service.authz.api.capi.invoice_access_token
import data.service.authz.api.capi.customer_access_token
import data.service.authz.api.capi.invoice_template_access_token
import data.service.authz.api.user
import data.service.authz.access
import data.service.authz.methods
import data.service.authz.whitelists

import input.capi.op
import input.payment_processing
import input.payouts
import input.webhooks
import input.reports
import input.tokens

api_name := "CommonAPI"
access_matrix := access.api[api_name]

access_mandatory := "mandatory"
access_discretionary := "discretionary"

access_requirements := {
    access_mandatory,
    access_discretionary
}

# Set of assertions which tell why operation under the input context is forbidden.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

forbidden[why] {
    not allowed_operation_for_auth_method
    why := {
        "code": "unknown_auth_method_forbids_operation",
        "description": sprintf("Unknown auth method for this operation: %v", [input.auth.method])
    }
}

forbidden[why] {
    access_violations[why]
}

# Restrictions

restrictions[restriction] {
    ip_replacement_forbidden
    restriction := {
        "capi": {
            "ip_replacement_forbidden": true
        }
    }
}

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

allowed[why] {
    allowed_operation_for_auth_method
    auth_method_allowed[why]
}

##

auth_method_allowed[why] {
    input.auth.method == "SessionToken"
    count(access_violations) == 0
    session_token_allowed[why]
}

auth_method_allowed[why] {
    input.auth.method == "ApiKeyToken"
    count(access_violations) == 0
    api_key_token_allowed[why]
}

auth_method_allowed[why] {
    input.auth.method == "InvoiceAccessToken"
    invoice_access_token.allowed[why]
}

auth_method_allowed[why] {
    input.auth.method == "CustomerAccessToken"
    customer_access_token.allowed[why]
}

auth_method_allowed[why] {
    input.auth.method == "InvoiceTemplateAccessToken"
    invoice_template_access_token.allowed[why]
}

##

session_token_allowed[why] {
    operation_universal
    why := {
        "code": "operation_universal",
        "description": "Operation is universally allowed"
    }
}

session_token_allowed[why] {
    access_status.owner
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

session_token_allowed[why] {
    role := access_status.roles[_]
    operations := user.operations_by_role(api_name, role)
    operations[_] == op.id
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [role.id])
    }
}

##

api_key_token_allowed[why] {
    operation_universal
    why := {
        "code": "operation_universal",
        "description": "Operation is universally allowed"
    }
}

api_key_token_allowed[why] {
    access_status.in_scope
    why := {
        "code": "api_key_scope_matches",
        "description": "Api key scope matches operation party"
    }
}

##

access_status = status {
    # NOTE
    # This is intentional. In there are no violations then the access status set
    # MUST NOT contain conflicting (i.e. more than one) status assertions.
    # Otherwise evaluation will end with a runtime error. Usually it would mean
    # that either incoming context or access matrix (access/data.yaml) is
    # malformed.
    status := access_status_set[_]
}

access_status_set[status] {
    operation_access_request[requirement][name]
    status := entity_access_requirement_status(name, requirement)
    # NOTE
    # This discards discretionary access status assertions (i.e. `status := true`).
    is_object(status)
}

access_violations[violation] {
    violation := access_status_set[_].violation
}

entity_access_requirement_status(name, req) = status {
    req == access_mandatory
    status := entity_access_status[name]
} else = status {
    req == access_discretionary
    not op_entity_specified[name]
    status := true
} else = status {
    req == access_discretionary
    entity_access_status[name]
    status := true
} else = status {
    violation := {
        "code": "missing_access",
        "description": sprintf(
            "Missing %s access for %s with id = %v",
            [req, name, format_entity_id(name)]
        )
    }
    status := {"violation": violation}
}

op_entity_specified[name] {
    # NOTE
    # Please take care to not misuse this when introducing something not exactly
    # entity-like in the protocol.
    op[name].id
}

format_entity_id(name) = s {
    s := op[name].id
} else = s {
    s := "undefined"
}

operation_access_request[requirement] = names {
    requirement := access_requirements[_]
    entities := access_matrix[requirement]
    names := { name | entities[name].operations[_] == op.id }
}

operation_universal {
    access_matrix.universal.operations[_] == op.id
}

entity_access_status["party"] = status {
    status := party_access_status(op.party.id)
}
entity_access_status["shop"] = status {
    status := shop_access_status(op.shop.id, op.party.id)
}
entity_access_status["invoice"] = status {
    status := invoice_access_status(op.invoice.id)
}
entity_access_status["invoice_template"] = status {
    status := invoice_template_access_status(op.invoice_template.id)
}
entity_access_status["customer"] = status {
    status := customer_access_status(op.customer.id)
}
entity_access_status["report"] = status {
    status := report_access_status(op.report.id)
}
entity_access_status["file"] = status {
    status := file_access_status(op.file.id)
}
entity_access_status["payout"] = status {
    status := payout_access_status(op.payout.id)
}
entity_access_status["webhook"] = status {
    status := webhook_access_status(op.webhook.id)
}

party_access_status(party_id) = status {
    user.is_owner(party_id)
    status := {"owner": true}
} else = status {
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_party_access(role)
    }
    roles[_]
    status := {"roles": roles}
} else = status {
    not input.user
    scope := input.auth.scope[_]
    scope.party.id == party_id
    status := {"in_scope": true}
}

shop_access_status(id, party_id) = status {
    user.is_owner(party_id)
    status := {"owner": true}
} else = status {
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_shop_access(id, role)
    }
    roles[_]
    status := {"roles": roles}
} else = status {
    not input.user
    scope := input.auth.scope[_]
    scope.party.id == party_id
    status := {"in_scope": true}
}

user_role_has_shop_access(shop_id, role) {
    role.scope.shop
    shop_id == role.scope.shop.id
}
user_role_has_shop_access(_, role) {
    user_role_has_party_access(role)
}

user_role_has_party_access(role) {
    not role.scope
}

invoice_access_status(id) = status {
    invoice := payment_processing.invoice
    invoice.id == id
    status := shop_access_status(invoice.shop.id, invoice.party.id)
}

invoice_template_access_status(id) = status {
    invoice_template := payment_processing.invoice_template
    invoice_template.id == id
    status := shop_access_status(invoice_template.shop.id, invoice_template.party.id)
}

customer_access_status(id) = status {
    customer := payment_processing.customer
    customer.id == id
    status := shop_access_status(customer.shop.id, customer.party.id)
}

report_access_status(id) = status {
    report := reports.report
    report.id == id
    status := shop_access_status(report.shop.id, report.party.id)
}

file_access_status(id) = status {
    report := reports.report
    report.files[_].id == id
    status := report_access_status(report.id)
}

payout_access_status(id) = status {
    payout := payouts.payout
    payout.id == id
    status := shop_access_status(payout.shop.id, payout.party.id)
}

webhook_access_status(id) = status {
    webhook := webhooks.webhook
    webhook.id == id
    status := party_access_status(webhook.party.id)
}

ip_replacement_forbidden {
    tokens.replacement_ip
    op.party.id != whitelists.ip_replacement_party_ids.entries[_]
}

allowed_operation_for_auth_method {
    operations_available := methods.permissions[input.auth.method].apis[api_name].operations
    operations_available[_] == op.id
}
