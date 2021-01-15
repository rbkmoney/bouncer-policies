package test.service.authz.api.capi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_get_refunds_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_get_refunds
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "org_role_allows_operation"
}

test_get_refunds_forbidden_context_mismatch {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_cancel_payment_fail
    ])
    not result.forbidden
    not result.allowed
}

test_forbidden_create_payment_resource {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_create_payment_resource
    ])
    result.forbidden
}

test_forbidden_invoicing_context_no_shop {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_no_shop_context
    ])
    not result.forbidden
    not result.allowed
}

test_forbidden_invoicing_context_no_party {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_no_party_context
    ])
    not result.forbidden
    not result.allowed
}

test_create_invoice_access_token_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice_access_token
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_insufficient_input_forbidden {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_insufficient_input_info
    ])
    not result.forbidden
    not result.allowed
}

test_get_refund_by_id_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_get_refund_by_id
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_rescind_invoice_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_rescind_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

capi_public_operation_ctx = util.deepmerge([
    fixtures.env_default,
    fixtures.requester_default,
    fixtures.user_default,
    fixtures.session_token_valid,
    fixtures.op_capi_empty
])

test_capi_allowed_by_session_token_1 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetAccountByID"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_2 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetCategories"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_3 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetCategoryByRef"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_4 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetLocationsNames"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_5 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutions"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_6 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionByRef"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_7 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPaymentTerms"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_8 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutMethods"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_9 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetPaymentInstitutionPayoutSchedules"}
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_10 {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "GetScheduleByRef"}
    not result.forbidden
    count(result.allowed) == 1
}

test_update_invoice_template_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_update_invoice_template
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_create_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_binding
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_get_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_get_binding
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_capi_session_token_and_owner_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_capi_get_binding
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_create_webhook_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_webhook
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_unknown_operation_forbidden_no_access {
    result := api.assertions with input as capi_public_operation_ctx with input.capi.op as {"id" : "NewOperation"}
    not result.forbidden
    not result.allowed
}
