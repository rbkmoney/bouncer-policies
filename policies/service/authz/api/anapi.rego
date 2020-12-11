package service.authz.api.anapi

import data.service.authz.api.utils

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
    not utils.user_is_owner(op.party.id)
    utils.user_has_any_role_for_op(op.id, op.party.id, api_name)
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
    result := utils.user_roles_by_operation(op.id, op.party.id, api_name)
    op.shops[i].id == result["result"][_].scope.shop.id
    shop := op.shops[i]
}

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

allowed[why] {
    utils.user_is_owner(op.party.id)
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

allowed[why] {
    result := utils.user_roles_by_operation(op.id, op.party.id, api_name)
    user_role_id := result["result"][_].id
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [user_role_id])
    }
}
