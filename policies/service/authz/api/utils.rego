package service.authz.api.utils

import data.service.authz.roles

user_is_owner {
    organization := org_by_operation
    input.user.id == organization.owner.id
}

user_has_any_role_for_op {
    user_roles_by_operation[_]
}

user_roles_by_operation [user_role] {
    user_role := org_by_operation.roles[_]
    input.abstract_op_id == roles.roles[user_role.id].apis[input.abstract_api_name].operations[_]
}

org_by_operation = org {
    org := input.user.orgs[_]
    org.id == input.abstract_party_id
}
