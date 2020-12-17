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

test_capi_operation_allowed {
    test_input := util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_abstract
    ])
    result0 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetAccountByID"}])
    count(result0.forbidden) == 0
    count(result0.allowed) == 1
    result1 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetCategories"}])
    count(result1.forbidden) == 0
    count(result1.allowed) == 1
    result2 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetCategoryByRef"}])
    count(result2.forbidden) == 0
    count(result2.allowed) == 1
    result3 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetLocationsNames"}])
    count(result3.forbidden) == 0
    count(result3.allowed) == 1
    result4 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetPaymentInstitutions"}])
    count(result4.forbidden) == 0
    count(result4.allowed) == 1
    result5 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetPaymentInstitutionByRef"}])
    count(result5.forbidden) == 0
    count(result5.allowed) == 1
    result6 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetPaymentInstitutionPaymentTerms"}])
    count(result6.forbidden) == 0
    count(result6.allowed) == 1
    result7 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetPaymentInstitutionPayoutMethods"}])
    count(result7.forbidden) == 0
    count(result7.allowed) == 1
    result8 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetPaymentInstitutionPayoutSchedules"}])
    count(result8.forbidden) == 0
    count(result8.allowed) == 1
    result9 := api.assertions with input as test_input with input.capi.op as util.deepmerge([{"id" : "GetScheduleByRef"}])
    count(result9.forbidden) == 0
    count(result9.allowed) == 1
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
