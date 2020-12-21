package test.service.authz.api.capi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_get_refunds_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_get_refunds
    ])
    count(result.forbidden) == 0
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
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_forbidden_invoicing_context_no_shop {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_no_shop_context
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_forbidden_invoicing_context_no_party {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_no_party_context
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_forbidden_invoicing_context_no_refund {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_no_refund_context
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_forbidden_invoicing_context_no_payment {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_no_payment_context
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_create_invoice_access_token_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_administrator,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice_access_token
    ])
    count(result.forbidden) == 0
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
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_get_refund_by_id_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_get_refund_by_id
    ])
    count(result.forbidden) == 0
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
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

capi_public_operation_ctx = operation_input {
    operation_input := util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_empty
    ])
}

test_capi_allowed_by_session_token_1 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetAccountByID"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_2 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetCategories"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_3 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetCategoryByRef"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_4 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetLocationsNames"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_5 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetPaymentInstitutions"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_6 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetPaymentInstitutionByRef"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_7 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetPaymentInstitutionPaymentTerms"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_8 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetPaymentInstitutionPayoutMethods"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_9 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetPaymentInstitutionPayoutSchedules"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_capi_allowed_by_session_token_10 {
    operation_input := capi_public_operation_ctx
    result := api.assertions with input as operation_input with input.capi.op as {"id" : "GetScheduleByRef"}
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_update_invoice_template_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_update_invoice_template
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_create_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_create_binding
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_get_binding_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_get_binding
    ])
    count(result.forbidden) == 0
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
    count(result.forbidden) == 0
    count(result.allowed) == 1
}
