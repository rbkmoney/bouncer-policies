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

access_requirements := {
    access_mandatory
}

# Set of assertions which tell why operation under the input context is forbidden.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

forbidden[why] {
    input.auth.method == "SessionToken"
    why := {
        "code": "operation_not_allowed_for_session_token",
        "description": "Operation not allowed for session token"
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
entity_access_status["identity"] = status {
    status := identity_access_status(op.identity.id)
}
entity_access_status["wallet"] = status {
    grant := try_get_wallet_grant()
    wallet_entity := entity.try_find_by_id("Wallet", op.wallet.id, wallet)
    status := wallet_grant_access_status(op.wallet.id, op.wallet_grant, wallet_entity.wallet.body)
} else = status {
    status := wallet_access_status(op.wallet.id)
}
entity_access_status["destination"] = status {
    grant := try_get_destination_grant()
    destination_entity := entity.try_find_by_id("Destination", op.destination.id, wallet)
    status := destination_grant_access_status(op.destination.id, op.destination_grant)
} else = status {
    status := destination_access_status(op.destination.id)
}
entity_access_status["withdrawal"] = status {
    status := withdrawal_access_status(op.withdrawal.id)
}
entity_access_status["w2w_transfer"] = status {
    status := w2w_transfer_access_status(op.w2w_transfer.id)
}
entity_access_status["report"] = status {
    status := report_access_status(op.report.id)
}
entity_access_status["file"] = status {
    status := file_access_status(op.file.id)
}
entity_access_status["webhook"] = status {
    status := webhook_access_status(op.webhook.id)
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
    party := identity.wallet.party
    userorg := user.org_by_party(party)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_identity_access(id, role)
    }
    roles[_]
    status := {"roles": roles}
}

user_role_has_identity_access(identity_id, role) {
    role.scope.identity
    identity_id == role.scope.identity.id
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
    {"grant": true}
}

wallet_access_status(id) = status {
    wallet_entity := entity.try_find_by_id("Wallet", id, wallet)
    party := wallet_entity.wallet.party
    userorg := user.org_by_party(party.id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_wallet_access(id, role)
    }
    roles[_]
    status := {"roles": roles}
}

user_role_has_wallet_access(wallet_id, role) {
    role.scope.wallet
    wallet_id == role.scope.wallet.id
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
    {"grant": true}
}

destination_access_status(id) = status {
    destination := entity.try_find_by_id("Destination", id, wallet)
    party := destination.wallet.party
    userorg := user.org_by_party(party.id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_destination_access(id, role)
    }
    roles[_]
    status := {"roles": roles}
}

user_role_has_destination_access(destination_id, role) {
    role.scope.destination
    destination_id == role.scope.destination.id
}
user_role_has_destination_access(_, role) {
    user_role_has_party_access(role)
}

withdrawal_access_status(id) = status {
    withdrawal := entity.try_find_by_id("Withdrawal", id, wallet)
    party := withdrawal.wallet.party
    wallet_id := withdrawal.wallet.wallet
    userorg := user.org_by_party(party.id)
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
    party := w2w_transfer.wallet.party
    wallet_id := w2w_transfer.wallet.wallet
    userorg := user.org_by_party(party.id)
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
    party := report.wallet.party
    identity_id := report.wallet.identity
    userorg := user.org_by_party(party.id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_identity_access(identity_id, role)
    }
    roles[_]
    status := {"roles": roles}
}

file_access_status(id) = status {
    # NOTE
    # mb put this in universal?
    status := {"owner": true}
}

webhook_access_status(id) = status {
    webhook := entity.try_find_by_id("WalletWebhook", id, wallet)
    party := webhook.wallet.party
    identity_id := webhook.wallet.identity
    userorg := user.org_by_party(party.id)
    roles := {
        role |
            role := userorg.roles[_]
            user_role_has_identity_access(identity_id, role)
    }
    roles[_]
    status := {"roles": roles}
}

try_get_wallet_grant() = grant {
    grant := grants[_]
    grant.wallet
}

try_get_destination_grant() = grant {
    grant := grants[_]
    grant.destination
}
