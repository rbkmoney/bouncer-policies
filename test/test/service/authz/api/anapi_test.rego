package test.authz.api.anapi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_anapi_restricted {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.restrictions == fixtures.op_anapi_restrictions
}

test_anapi_allowed_org_owner {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
    not result.forbidden
    count(result.allowed) == 1
    not result.restrictions
}

test_anapi_allowed_operation_no_shops {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_anapi_no_shops
    ])
    not result.forbidden
    count(result.allowed) == 1
    not result.restrictions
}

test_anapi_restricted_several_shops_operation {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_anapi_several_shops
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.restrictions == fixtures.op_anapi_restrictions
}

test_anapi_restricted_several_shops_several_roles_operation {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_several_roles,
        fixtures.session_token_valid,
        fixtures.op_anapi_several_shops
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.restrictions == fixtures.op_anapi_restrictions_several_shops
}

test_anapi_forbidden_operation_no_role {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_anapi_reports
    ])
    not result.forbidden
    not result.allowed
    not result.restrictions
}

test_anapi_forbidden_operation_no_role_2 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default_other_role,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
    not result.forbidden
    not result.allowed
    not result.restrictions
}

test_anapi_forbidden_operation_no_role_3 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_no_roles,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
    not result.forbidden
    not result.allowed
    not result.restrictions
}

test_anapi_forbidden_operation_no_shops {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default_other_role,
        fixtures.session_token_valid,
        fixtures.op_anapi_no_shops
    ])
    not result.forbidden
    not result.allowed
    not result.restrictions
}

test_anapi_forbidden_operation_auth_invalid {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_anapi
    ])
    count(result.forbidden) == 1
    count(result.allowed) == 1
    result.restrictions == fixtures.op_anapi_restrictions
}
