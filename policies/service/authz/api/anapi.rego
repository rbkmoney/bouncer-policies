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
    not utils.user_is_owner with input.abstract_party_id as op.party.id
    utils.user_has_any_role_for_op
        with input.abstract_party_id as op.party.id
        with input.abstract_op_id as op.id
        with input.abstract_api_name as api_name
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
    op.shops[i].id == utils.user_roles_by_operation[_].scope.shop.id
        with input.abstract_party_id as op.party.id
        with input.abstract_op_id as op.id
        with input.abstract_api_name as api_name
    shop := op.shops[i]
}

# Set of assertions which tell why operation under the input context is allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

allowed[why] {
    utils.user_is_owner with input.abstract_party_id as op.party.id
    why := {
        "code": "org_ownership_allows_operation",
        "description": "User is owner of organization that is subject of this operation"
    }
}

allowed[why] {
    user_role_id := utils.user_roles_by_operation[_].id
        with input.abstract_party_id as op.party.id
        with input.abstract_op_id as op.id
        with input.abstract_api_name as api_name
    why := {
        "code": "org_role_allows_operation",
        "description": sprintf("User has role that permits this operation: %v", [user_role_id])
    }
}
