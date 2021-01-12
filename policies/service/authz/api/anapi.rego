package service.authz.api.anapi

import data.service.authz.api.user

import input.anapi.op
import data.service.authz.roles

api_name := "AnalyticsAPI"

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
    user.is_owner(op.party.id)
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

allowed[why] {
    user_roles := user.roles_by_operation(op.party.id, api_name, op.id)
    user_role_id := user_roles[_].id
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [user_role_id])
    }
}
