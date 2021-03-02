package test.service.authz.api.capi.customer_access_token

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_customer_access_token_allows_create_payment_resource {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_create_payment_resource
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_allows_get_customer_by_id {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_by_id,
        context.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_allows_create_binding {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_create_binding,
        context.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_allows_get_binding {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_binding,
        context.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_allows_get_customer_events {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_customer_events,
        context.payproc_customer
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_forbids_get_invoice {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.customer_access_token_valid,
        context.op_capi_get_invoice,
        context.payproc_invoice
    ])
}
