package service.authz.api.anapi

import data.service.authz.api.user
import data.service.authz.access

import input.anapi.op
import input.reports
import data.service.authz.roles

api_name := "AnalyticsAPI"
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

# Restrictions

restrictions[what] {
    not user.is_owner(op.party.id)
    user.roles_by_operation(op.party.id, api_name, op.id)[_]
    what := {
        "anapi": {
            "op": {
                "shops": [shop | shop := op_shop_in_scope[_]]
            }
        }
    }
}

op_shop_in_scope[shop] {
    some i
    user_roles := user.roles_by_operation(op.party.id, api_name, op.id)
    op.shops[i].id == user_roles[_].scope.shop.id
    shop := op.shops[i]
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
    s := op[name].id
} else = s {
    s := "undefined"
}

operation_access_request[requirement] = names {
    requirement := access_requirements[_]
    entities := access_matrix[requirement]
    names := { name | entities[name].operations[_] == op.id }
}

entity_access_status["party"] = status {
    status := party_access_status(op.party.id)
}
entity_access_status["shop"] = status {
    status := shop_access_status(op.shop.id, op.party.id)
}
entity_access_status["report"] = status {
    status := report_access_status(op.report.id)
}
entity_access_status["file"] = status {
    status := file_access_status(op.file.id)
}

dd := user.org_by_party(op.party.id)

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
