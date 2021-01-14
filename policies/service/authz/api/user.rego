package service.authz.api.user

import data.service.authz.roles

is_owner(party_id) {
    organization := org_by_party(party_id)
    input.user.id == organization.owner.id
}

roles_by_operation(party_id, api_name, op_id) = user_roles {
    organization := org_by_party(party_id)
    user_roles := { user_role |
        user_role := organization.roles[_]
        op_id == roles.roles[user_role.id].apis[api_name].operations[_]
    }
}

org_by_party(party_id) = org {
    org := input.user.orgs[_]
    org.id == party_id
}
