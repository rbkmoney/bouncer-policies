package service.authz.api.utils

import data.service.authz.roles

user_is_owner(op_party_id) {
    organization := org_by_operation(op_party_id)
    input.user.id == organization.owner.id
}

user_has_any_role_for_op(op_id, op_party_id, api_name) {
    user_roles_by_operation(op_id, op_party_id, api_name)[_]
}

user_roles_by_operation(op_id, op_party_id, api_name) = result {
    user_role := org_by_operation(op_party_id).roles[_]
    op_id == roles.roles[user_role.id].apis[api_name].operations[_]
    result := {"result" : [user_role]}
}

org_by_operation(op_party_id) = org {
    org := input.user.orgs[_]
    org.id == op_party_id
}
