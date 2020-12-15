package test.service.authz.api.capi.invoice_access_token

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_invoice_access_token_valid_1 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_payment_resource
    ])
    count(result.forbidden) == 0
    result.allowed[_].code == "invoice_access_token_allows_tokenization"
}

test_invoice_access_token_valid_2 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice
    ])
    count(result.forbidden) == 0
    result.allowed[_].code == "invoice_access_token_allows_operation"
}

test_invoice_access_token_expired {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_expired,
        fixtures.op_capi_create_payment_resource
    ])
    result.forbidden[_].code == "auth_expired"
}

test_invoice_access_token_invalid_party {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid_party_2,
        fixtures.op_capi_create_payment_resource
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_invoice_access_token_invalid_invoice {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice_2
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_invoice_access_token_invalid_operation_1 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_refund
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_invoice_access_token_invalid_operation_2 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_invoice
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 0
}

test_invoice_access_token_valid_capi_get_invoice_payment_methods{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice_payment_methods
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_invoice_access_token_valid_capi_get_invoice_events{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice_events
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_invoice_access_token_valid_capi_create_payment{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_payment
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_invoice_access_token_valid_capi_get_payments{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_payments
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_invoice_access_token_valid_capi_get_payment_by_id{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_payment_by_id
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_invoice_access_token_valid_capi_cancel_payment{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_cancel_payment
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}

test_invoice_access_token_valid_capi_capture_payment{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_capture_payment
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
}
