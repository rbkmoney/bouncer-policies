package test.service.authz.api.orgmgmt

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_orgmgmt_allowed_org_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_orgmgmt_create_invitation
    ])
}

test_forbidden_user_without_orgs {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_without_orgs,
        context.session_token_valid,
        context.op_orgmgmt_create_invitation
    ])
}
