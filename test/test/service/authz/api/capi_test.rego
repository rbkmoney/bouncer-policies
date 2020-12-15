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

test_get_payment_institution_payout_schedules_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_get_payment_institution_payout_schedules
    ])
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
