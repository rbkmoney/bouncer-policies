package test.authz.api.anapi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_anapi_restricted {
    util.is_restricted_with(fixtures.op_anapi_restrictions) with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
}

test_anapi_restricted_operation_no_shops {
    result := api.judgement with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_anapi_no_shops
    ])
}

test_anapi_allowed_org_owner {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
}

test_anapi_allowed_operation_no_shops {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_anapi_no_shops
    ])
}

test_anapi_restricted_several_shops_operation {
    util.is_restricted_with(fixtures.op_anapi_restrictions) with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_anapi_several_shops
    ])
}

test_anapi_restricted_several_shops_several_roles_operation {
    util.is_restricted_with(fixtures.op_anapi_restrictions_several_shops) with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_several_roles,
        fixtures.session_token_valid,
        fixtures.op_anapi_several_shops
    ])
}

test_anapi_restricted_several_shops_several_roles_another_party_operation {
    util.is_restricted_with(fixtures.op_anapi_restrictions_several_shops) with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_several_roles_another_party,
        fixtures.session_token_valid,
        fixtures.op_anapi_several_shops
    ])
}

test_anapi_administrator_manager {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_manager,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
}

test_anapi_forbidden_operation_no_role {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_anapi_reports
    ])
}

test_anapi_forbidden_operation_no_role_2 {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default_other_role,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
}

test_anapi_forbidden_operation_no_role_3 {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_no_roles,
        fixtures.session_token_valid,
        fixtures.op_anapi
    ])
}

test_anapi_forbidden_operation_no_shops {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default_other_role,
        fixtures.session_token_valid,
        fixtures.op_anapi_no_shops
    ])
}

test_anapi_forbidden_operation_auth_invalid {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_anapi
    ])
}

test_get_report_allowed {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_anapi_get_report,
        fixtures.reports_report
    ])
}

test_create_report_allowed {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_bookkeeper,
        fixtures.session_token_valid,
        fixtures.op_anapi_create_report
    ])
}

test_create_report_allowed_owner {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_bookkeeper,
        fixtures.session_token_valid,
        fixtures.op_anapi_create_report
    ])
}

test_download_file_allowed_administrator {
    util.is_allowed with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_shop,
        fixtures.session_token_valid,
        fixtures.op_anapi_download_file,
        fixtures.reports_report
    ])
}

test_download_missing_file_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_shop,
        fixtures.session_token_valid,
        fixtures.op_anapi_download_missing_file,
        fixtures.reports_report
    ])
}

test_download_file_invalid_shop_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_shop,
        fixtures.session_token_valid,
        fixtures.op_anapi_download_file_invalid_shop,
        fixtures.reports_report
    ])
}

test_download_file_invalid_party_forbidden {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator_owner_another_party,
        fixtures.session_token_valid,
        fixtures.op_anapi_download_file_invalid_party,
        fixtures.reports_report
    ])
}
