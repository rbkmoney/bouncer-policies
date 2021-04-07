package service.authz.api.orgmgmt

import data.service.authz.api.user
import data.service.authz.access
import data.service.authz.roles

import input.orgmgmt.op


api_name := "OrgManagement"
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
    not role_free_operation
    access_violations[why]
}

forbidden[why] {
    input.auth.method == "SessionToken"
    membership_operation
    membership_violations[why]
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
    role := operation_roles[_]
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
    count(access_violations) == 0
    status := access_status_set[_]
}

access_violations[violation] {
    violation := access_status_set[_].violation
}

operation_universal {
    access_matrix.universal.operations[_] == op.id
}

access_status_set[status] {
    operation_access_request[requirement][name]
    status := entity_access_requirement_status(name, requirement)
    # NOTE
    # This discards discretionary access status assertions (i.e. `status := true`).
    is_object(status)
}

operation_access_request[requirement] = names {
    requirement := access_requirements[_]
    entities := access_matrix[requirement]
    names := { name | entities[name].operations[_] == op.id }
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

entity_access_status["organization"] = status {
    status := organization_access_status(op.organization.id)
}

organization_access_status(id) = status {
    user.is_owner(id)
    status := {"owner": true}
} else = status {
    userorg := user.org_by_party(id)
    roles := { role | role := userorg.roles[_] }
    roles[_]
    status := {"roles": roles}
}

operation_roles[role] {
    role := access_status.roles[_]
    operations := user.operations_by_role(api_name, role)
    operations[_] == op.id
}

role_free_operation
    { op.id == "joinOrg" }

membership_violations[violation]{
   status := membership_rights_status(op.organization.id)
   is_object(status)
   violation := status.violation
}

membership_rights_status(id) = status {
   op.member
   org := op.member.orgs[_]
   org.id == id
   status := {"member": true}
} else = status {
   violation := {
        "code": "missing_membership",
        "description": sprintf(
            "The user with id = %s in not a memeber of organization with id = %s",
            [op.member.id, id]
        )
   }
   status := {"violation": violation}
}

membership_operation
    { op.id == "getOrgMember" }
    { op.id == "expelOrgMember" }
    { op.id == "assignMemberRole" }
    { op.id == "removeMemberRole" }