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
entity_access_status["file"] = status {
    status := file_access_status(op.file)
}
entity_access_status["webhook"] = status {
    webhook := entity.try_find_by_id("WalletWebhook", op.webhook, wallet)
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
    identity := entity.try_find_by_id("Identity", id, wallet)
    party_id := identity.wallet.party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_identity_access(id, role)
    }
    roles[_]
    status := {"roles": roles}
}

user_role_has_identity_access(_, role) {
    user_role_has_party_access(role)
}

wallet_grant_access_status(id, grant, body) = status {
    grant.wallet == id
    grant.body == body
    exp := time.parse_rfc3339_ns(grant.expires_on)
    now := time.parse_rfc3339_ns(input.env.now)
    now < exp
    status := {"grant": true}
}

wallet_access_status(id) = status {
    grant := wallet_grants[_]
    wallet_entity := entity.try_find_by_id("Wallet", id, wallet)
    status := wallet_grant_access_status(id, grant, wallet_entity.wallet.body)
} else = status {
    wallet_entity := entity.try_find_by_id("Wallet", id, wallet)
    party_id := wallet_entity.wallet.party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_wallet_access(id, role)
    }
    roles[_]
    status := {"roles": roles}
}

user_role_has_wallet_access(_, role) {
    user_role_has_party_access(role)
}

user_role_has_party_access(role) {
    not role.scope
}

destination_grant_access_status(id, grant) = status {
    grant.destination == id
    exp := time.parse_rfc3339_ns(grant.expires_on)
    now := time.parse_rfc3339_ns(input.env.now)
    now < exp
    status := {"grant": true}
}

destination_access_status(id) = status {
    grant := destination_grants[_]
    status := destination_grant_access_status(id, grant)
} else = status {
    destination := entity.try_find_by_id("Destination", id, wallet)
    party_id := destination.wallet.party
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_destination_access(id, role)
    }
    roles[_]
    status := {"roles": roles}
}

user_role_has_destination_access(_, role) {
    user_role_has_party_access(role)
}

withdrawal_access_status(id) = status {
    withdrawal := entity.try_find_by_id("Withdrawal", id, wallet)
    party_id := withdrawal.wallet.party
    wallet_id := withdrawal.wallet.wallet
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_wallet_access(wallet_id, role)
    }
    roles[_]
    status := {"roles": roles}
}

w2w_transfer_access_status(id) = status {
    w2w_transfer := entity.try_find_by_id("W2WTransfer", id, wallet)
    party_id := w2w_transfer.wallet.party
    wallet_id := w2w_transfer.wallet.wallet
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_wallet_access(wallet_id, role)
    }
    roles[_]
    status := {"roles": roles}
}

report_access_status(id) = status {
    report := entity.try_find_by_id("WalletReport", id, wallet)
    party_id := report.wallet.party
    identity_id := report.wallet.identity
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_identity_access(identity_id, role)
    }
    roles[_]
    status := {"roles": roles}
}

file_access_status(id) = status {
    report := entity.try_find_first("WalletReport", wallet)
    report.wallet.report.files[_] == id
    status := report_access_status(report.id)
}

webhook_access_status(id) = status {
    webhook := entity.try_find_by_id("WalletWebhook", id, wallet)
    party_id := webhook.wallet.party
    identity_id := webhook.wallet.identity
    userorg := user.org_by_party(party_id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_identity_access(identity_id, role)
    }
    roles[_]
    status := {"roles": roles}
}

wallet_grants[grant] {
    grant := grants[_]
    grant.wallet
}

destination_grants[grant] {
    grant := grants[_]
    grant.destination
}
