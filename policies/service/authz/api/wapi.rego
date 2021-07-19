package service.authz.api.wapi

import data.service.authz.api.user
import data.service.authz.api.entity
import data.service.authz.access

import input.wapi.op
import input.wapi.grants
import input.wallet

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
    input.auth.method != "SessionToken"
    why := {
        "code": "unknown_auth_method_forbids_operation",
        "description": sprintf("Unknown auth method for this operation: %v", [input.auth.method])
    }
}

forbidden[why] {
    input.auth.method == "SessionToken"
    access_violations[why]
}

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

allowed[why] {
    input.auth.method == "SessionToken"
    count(access_violations) == 0
    session_token_allowed[why]
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
    entities := access_matrix[requirement]
    names := { name | entities[name].operations[_] == op.id }
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
}

identity_access_status(id) = status {
    identities := entities["Identity"]
    party_id := identities[id].party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_party_access(role)
    }
    roles[_]
    status := {"roles": roles}
}

wallet_access_status(id) = status {
    wallet_entities := entities["Wallet"]
    grant := wallet_grants[_]
    grant.wallet == id
    grant.body == wallet_entities[id].wallet.body
    exp := time.parse_rfc3339_ns(grant.expires_on)
    now := time.parse_rfc3339_ns(input.env.now)
    now < exp
    status := {"grant": true}
} else = status {
    wallet_entities := entities["Wallet"]
    party_id := wallet_entities[id].party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_party_access(role)
    }
    roles[_]
    status := {"roles": roles}
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
    destinations := entities["Destination"]
    party_id := destinations[id].party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_party_access(role)
    }
    roles[_]
    status := {"roles": roles}
}

withdrawal_access_status(id) = status {
    withdrawals := entities["Withdrawal"]
    party_id := withdrawals[id].party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_party_access(role)
    }
    roles[_]
    status := {"roles": roles}
}

w2w_transfer_access_status(id) = status {
    w2w_transfers := entities["W2WTransfer"]
    party_id := w2w_transfers[id].party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_party_access(role)
    }
    roles[_]
    status := {"roles": roles}
}

report_access_status(id) = status {
    reports := entities["WalletReport"]
    status := identity_access_status(reports[id].wallet.identity)
}

webhook_access_status(id) = status {
    webhooks := entities["WalletWebhook"]
    status := identity_access_status(webhooks[id].wallet.identity)
}

wallet_grants[grant] {
    grant := grants[_]
    grant.wallet
}

destination_grants[grant] {
    grant := grants[_]
    grant.destination
}

entities[type] = out {
    type := wallet[_].type
    out := { id: entity |
        entity := wallet[_]
        id := entity.id
        entity.type == type
    }
}
