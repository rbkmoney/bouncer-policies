package service.authz.api.utils

import data.service.authz.roles

user_is_owner(party_id) {
    organization := org_by_operation(party_id)
    input.user.id == organization.owner.id
}

# user_has_any_role_for_op {
#     user_roles_by_operation[_]
# }

user_roles_by_operation(party_id, api_name, op_id) = user_roles {
    organization := org_by_operation(party_id)
    user_roles := { user_role |
        user_role := organization.roles[_]
        op_id == roles.roles[user_role.id].apis[api_name].operations[_]
    }
}

org_by_operation(party_id) = org {
    org := input.user.orgs[_]
    org.id == party_id
}
