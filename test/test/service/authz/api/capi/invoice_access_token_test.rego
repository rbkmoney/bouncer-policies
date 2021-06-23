package test.service.authz.api.capi.invoice_access_token

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_invoice_access_token_valid_1 {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_payment_resource
    ])
    not result.forbidden
    result.allowed[_].code == "invoice_access_token_allows_tokenization"
}

test_invoice_access_token_valid_2 {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_invoice,
        context.payproc_invoice
    ])
    not result.forbidden
    result.allowed[_].code == "invoice_access_token_allows_operation"
}

test_invoice_access_token_expired {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_expired,
        context.op_capi_create_payment_resource
    ])
    result.forbidden[_].code == "auth_expired"
}

test_invoice_access_token_invalid_party {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid_party_2,
        context.op_capi_create_payment_resource
    ])
    not result.forbidden
    not result.allowed
}

test_invoice_access_token_invalid_invoice {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_invoice_2,
        context.payproc_invoice_2
    ])
    not result.forbidden
    not result.allowed
}

test_invoice_access_token_invalid_operation_1 {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_refund,
        context.payproc_invoice
    ])
    result.forbidden # Explicitly forbidden by auth method check
    not result.allowed
}

test_invoice_access_token_invalid_operation_2 {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_invoice
    ])
    result.forbidden # Explicitly forbidden by auth method check
    not result.allowed
}

test_invoice_access_token_allows_get_invoice_payment_methods {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_invoice_payment_methods,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_allows_get_invoice_events {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_invoice_events,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_allows_create_payment {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_create_payment,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_allows_get_payment_by_id {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_payment_by_id,
        context.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_allows_get_payments {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_get_payments,
        context.payproc_invoice
    ])
}

test_invoice_access_token_forbids_cancel_payment {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.invoice_access_token_valid,
        context.op_capi_cancel_payment,
        context.payproc_invoice
    ])
}
