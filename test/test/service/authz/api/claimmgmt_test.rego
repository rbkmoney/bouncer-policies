package test.authz.api.claimmgmt

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context
import data.test.service.authz.fixtures.restrictions

test_claimmgmt_allowed_org_owner {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_claimmgmt_createClaim
    ])
}

test_claimmgmt_forbidden_user_without_orgs {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_without_orgs,
        context.session_token_valid,
        context.op_claimmgmt_createClaim
    ])
}

test_claimmgmt_allowed_administrator {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.session_token_valid,
        context.op_claimmgmt_createClaim
    ])
}

test_claimmgmt_forbidden_not_exist_operation {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_claimmgmt_not_exist_operation
    ])
}

test_claimmgmt_forbidden_another_auth_method {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_administrator,
        context.invoice_access_token_valid,
        context.op_claimmgmt_createClaim
    ])
}

test_claimmgmt_allowed_universal_opeartion {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_claimmgmt_searchClaims
    ])
}

test_claimmgmt_forbidden_operation_no_role {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_claimmgmt_createClaim
    ])
}

test_claimmgmt_forbidden_operation_no_role_2 {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default_other_role,
        context.session_token_valid,
        context.op_claimmgmt_createClaim
    ])
}

test_claimmgmt_forbidden_operation_no_role_3 {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_no_roles,
        context.session_token_valid,
        context.op_claimmgmt_createClaim
    ])
}

test_claimmgmt_forbidden_operation_auth_invalid {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.invoice_access_token_valid,
        context.op_claimmgmt_createClaim
    ])
}
