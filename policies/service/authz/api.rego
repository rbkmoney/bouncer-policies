package service.authz.api

import data.service.authz.api.invoice_access_token
import data.service.authz.blacklists
import data.service.authz.roles

assertions := {
    "forbidden" : { why | forbidden[why] },
    "allowed"   : { why | allowed[why] }
}

# Set of assertions which tell why operation under the input context is forbidden.
# When the set is empty operation is not explicitly forbidden.
# Each element must be either a string `"code"` or a 2-item array of the form:
# ```
# ["code", "description"]
# ```
forbidden[why] {
    input
    not input.auth.method
    why := {
        "code": "auth_required",
        "description": "Authorization is required"
    }
}

forbidden[why] {
    exp := time.parse_rfc3339_ns(input.auth.expiration)
    now := time.parse_rfc3339_ns(input.env.now)
    now > exp
    why := {
        "code": "auth_expired",
        "description": sprintf("Authorization is expired at: %s", [input.auth.expiration])
    }
}

forbidden[why] {
    ip := input.requester.ip
    blacklist := blacklists.source_ip_range
    matches := net.cidr_contains_matches(blacklist, ip)
    matches[_]
    ranges := [ range | matches[_][0] = i; range := blacklist[i] ]
    why := {
        "code": "ip_range_blacklisted",
        "description": sprintf(
            "Requester IP address is blacklisted with ranges: %v",
            [concat(", ", ranges)]
        )
    }
}

warnings[why] {
    not blacklists.source_ip_range
    why := "Blacklist 'source_ip_range' is not defined, blacklisting by IP will NOT WORK."
}

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be either a string `"code"` or a 2-item array of the form:
# ```
# ["code", "description"]
# ```
allowed[why] {
    input.auth.method == "SessionToken"
    input.user
    org_allowed[why]
}

allowed[why] {
    input.auth.method == "InvoiceAccessToken"
    invoice_access_token.allowed[why]
}

org_allowed[why] {
    org := org_by_operation
    org.owner == input.user.id
    why := {
        "code": "user_is_owner",
        "description": "User is the organisation owner itself"
    }
}

org_allowed[why] {
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
    shop == input.capi.op.shop.id
}

scopename_by_role[i] = "*" {
    role := org_by_operation.roles[i]
    not role.scope
}

# Get role to perform the operation in context.
role_by_operation = role_by_id[id]
    { id = input.capi.op.id }
    { id = input.orgmgmt.op.id }
    { id = input.shortener.op.id }

# A mapping of role names to role operations.
role_by_id[operation] = [rolename] {
    operation := roles.roles[i].operations[_]
    org_by_operation.roles[_].id == roles.roles[i].name
    rolename := roles.roles[i].name
}

# Context of an organisation which is being operated upon.
org_by_operation = org_by_id[id]
    { id = input.capi.op.party.id }
    { id = input.orgmgmt.op.organization.id }
    { id = input.shortener.op.party.id }

# A mapping of org ids to organizations.
org_by_id := { org.id: org | org := input.user.orgs[_] }
