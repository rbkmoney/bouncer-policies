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
    not result.forbidden
    result.allowed[_].code == "invoice_access_token_allows_tokenization"
}

test_invoice_access_token_valid_2 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice,
        fixtures.payproc_invoice
    ])
    not result.forbidden
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
    not result.forbidden
    not result.allowed
}

test_invoice_access_token_invalid_invoice {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice_2,
        fixtures.payproc_invoice_2
    ])
    not result.forbidden
    not result.allowed
}

test_invoice_access_token_invalid_operation_1 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_refund,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    not result.allowed
}

test_invoice_access_token_invalid_operation_2 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_invoice
    ])
    not result.forbidden
    not result.allowed
}

test_invoice_access_token_allows_get_invoice_payment_methods {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice_payment_methods,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_allows_get_invoice_events {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_invoice_events,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_allows_create_payment {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_create_payment,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_allows_get_payment_by_id {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_payment_by_id,
        fixtures.payproc_invoice
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_access_token_forbids_get_payments {
    util.is_forbidden with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_access_token_valid,
        fixtures.op_capi_get_payments,
        fixtures.payproc_invoice
    ])
}
