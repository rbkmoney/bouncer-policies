package service.authz.api.wapi

import data.service.authz.api.user
import data.service.authz.access
import data.service.authz.methods

import input.wapi.op
import input.wapi.grants
import input.wallet as entities

api_name := "WalletAPI"
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
    access_violations[why]
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

session_token_allowed[why] {
    access_status.grant
    why := {
        "code": "grant_allows_operation",
        "description": "User has grant that permits this operation"
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
    count(access_violations) == 0
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
    not op[name]
    status := true
} else = status {
    req == access_discretionary
    status := entity_access_status[name]
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

format_entity_id(name) = s {
    s := op[name]
} else = s {
    s := "undefined"
}

operation_access_request[requirement] = names {
    requirement := access_requirements[_]
    find_entity := access_matrix[requirement]
    names := { name | find_entity[name].operations[_] == op.id }
}

operation_universal {
    access_matrix.universal.operations[_] == op.id
}

entity_access_status["party"] = status {
    status := party_access_status(op.party)
}
entity_access_status["identity"] = status {
    status := identity_access_status(op.identity)
}
entity_access_status["wallet"] = status {
    status := wallet_access_status(op.wallet)
}
entity_access_status["destination"] = status {
    status := destination_access_status(op.destination)
}
entity_access_status["withdrawal"] = status {
    status := withdrawal_access_status(op.withdrawal)
}
entity_access_status["w2w_transfer"] = status {
    status := w2w_transfer_access_status(op.w2w_transfer)
}
entity_access_status["report"] = status {
    status := report_access_status(op.report)
}
entity_access_status["webhook"] = status {
    status := webhook_access_status(op.webhook)
}

party_access_status(id) = status {
    user.is_owner(id)
    status := {"owner": true}
} else = status {
    userorg := user.org_by_party(id)
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
    scope.party.id == id
    status := {"in_scope": true}
}


identity_access_status(id) = status {
    identity := find_entity["Identity"][id]
    status := party_access_status(identity.party)
}

wallet_access_status(id) = status {
    wallet := find_entity["Wallet"][id]
    grant := wallet_grants[_]
    grant.wallet == id
    grant.body >= wallet.wallet.body
    exp := time.parse_rfc3339_ns(grant.expires_on)
    now := time.parse_rfc3339_ns(input.env.now)
    now < exp
    status := {"grant": true}
} else = status {
    wallet := find_entity["Wallet"][id]
    status := party_access_status(wallet.party)
}

user_role_has_party_access(role) {
    not role.scope
}

destination_access_status(id) = status {
    grant := destination_grants[_]
    grant.destination == id
    exp := time.parse_rfc3339_ns(grant.expires_on)
    now := time.parse_rfc3339_ns(input.env.now)
    now < exp
    status := {"grant": true}
} else = status {
    destination := find_entity["Destination"][id]
    status := party_access_status(destination.party)
}

withdrawal_access_status(id) = status {
    withdrawal := find_entity["Withdrawal"][id]
    status := party_access_status(withdrawal.party)
}

w2w_transfer_access_status(id) = status {
    transfer := find_entity["W2WTransfer"][id]
    userorg := user.org_by_party(transfer.party)
    status := party_access_status(transfer.party)
}

report_access_status(id) = status {
    report := find_entity["WalletReport"][id]
    status := identity_access_status(report.wallet.identity)
}

webhook_access_status(id) = status {
    webhook := find_entity["WalletWebhook"][id]
    status := identity_access_status(webhook.wallet.identity)
}

wallet_grants[grant] {
    grant := grants[_]
    grant.wallet
}

destination_grants[grant] {
    grant := grants[_]
    grant.destination
}

find_entity[type] = out {
    type := entities[_].type
    out := { id: entity |
        entity := entities[_]
        id := entity.id
        entity.type == type
    }
}

allowed_operation_for_auth_method {
    operations_available := methods.permissions[input.auth.method].apis[api_name].operations
    operations_available[_] == op.id
}
