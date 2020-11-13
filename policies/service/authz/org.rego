package service.authz.org

import data.service.authz.roles

allowed[why] {
    org := org_by_operation
    org.owner.id == input.user.id
    why := {
        "code": "user_is_owner",
        "description": "User is the organisation owner itself"
    }
}

allowed[why] {
    rolename := role_by_operation[_]
    org_by_operation.roles[i].id == rolename
    scopename := scopename_by_role[i]
    why := {
        "code": "user_has_role",
        "description": sprintf("User has role %s in scope %v", [rolename, scopename])
    }
}

scopename_by_role[i] = sprintf("shop:%s", [shop]) {
    role := org_by_operation.roles[i]
    shop := role.scope.shop.id
    shop == operation_shop_id[shop]
}

operation_shop_id[id]
    { id := input.capi.op.shop.id }
    { id := input.anapi.op.shops[_].id }

scopename_by_role[i] = "*" {
    role := org_by_operation.roles[i]
    not role.scope
}

# Get role to perform the operation in context.
role_by_operation = role_by_id[id]
    { id = input.capi.op.id }
    { id = input.orgmgmt.op.id }
    { id = input.shortener.op.id }
    { id = input.anapi.op.id }

# A mapping of operations to role names.
role_by_id[op] = rolenames {
    op := operations[_]
    rolenames := { i |
        role := roles.roles[i]
        role.apis[_].operations[_] == op
    }
}

# A set of all known operations.
operations[op] {
    role := roles.roles[i]
    api := api_by_op
    op := role.apis[api].operations[_]
}

# Get API name by input op context
api_by_op = api
{
    input.capi
    api := "CommonAPI"
}
{
    input.orgmgmt
    api := "OrgManagement"
}
{
    input.shortener
    api := "UrlShortener"
}
{
    input.anapi
    api := "AnalyticsAPI"
}

# Context of an organisation which is being operated upon.
org_by_operation = org_by_id[id]
    { id = input.capi.op.party.id }
    { id = input.orgmgmt.op.organization.id }
    { id = input.anapi.op.party.id}

# A mapping of org ids to organizations.
org_by_id := { org.id: org | org := input.user.orgs[_] }

# A set of all user organizations.
organizations[org] {
    org := input.user.orgs[_]
}
