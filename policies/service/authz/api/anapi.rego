package service.authz.api.anapi

import input.anapi.op
import data.service.authz.org
import data.service.authz.roles

api_name := "AnalyticsAPI"

# Set of assertions which tell why operation under the input context is forbidden.
# When the set is empty operation is not explicitly forbidden.
# Each element must be either a string `"code"` or a 2-item array of the form:
# ```
# ["code", "description"]
# ```
forbidden[why] {
    input.auth.method != "SessionToken"
    why := {
        "code": "unknown_auth_method_forbids_operation",
        "description": "Unkown auth method for this operation"
    }
}

forbidden[why] {
    not user_can_do_op
    why := {
        "code": "user_rights_forbid_operation",
        "description": "User has no rights for this operation"
    }
}

# Restrictions

restrictions[what] {
    input.auth.method == "SessionToken"
    not user_is_owner
    user_has_role_for_op
    what := {
        "op": {
            "shops": [{"id": id} | id := op_shop_in_scope[_].id]
        }
    }
}

op_shop_in_scope[shop] {
    some i
    organization := org.org_by_operation
    op.shops[i].id == organization.roles[_].scope.shop.id
    shop := op.shops[i]
}

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be a 2-item array of the following form:
# ```
# ["code", "description"]
# ```
allowed[why] {
    input.auth.method == "SessionToken"
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

allowed[why] {
    user_is_owner
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

allowed[why] {
    user_has_role_for_op
    why := {
        "code": "org_role_allows_operation",
        "description": "User has role that permits this operation"
    }
}

user_can_do_op
    { user_is_owner }
    { user_has_role_for_op }

user_is_owner {
    organization := org.org_by_operation
    input.user.id == organization.owner.id
}

user_has_role_for_op {
    user_role := org_by_operation.roles[_]
    op.id == roles.roles[user_role.id].apis[api_name].operations[_]
}

org_by_operation = org_by_id[id] {
    id = input.anapi.op.party.id
}

org_by_id := { org.id: org | org := input.user.orgs[_] }