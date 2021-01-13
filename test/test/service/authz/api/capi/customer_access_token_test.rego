package test.service.authz.api.capi.customer_access_token

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_customer_access_token_valid_capi_create_payment_resource {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.customer_access_token_valid,
        fixtures.op_capi_create_payment_resource
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_valid_capi_get_customer_by_id{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.customer_access_token_valid,
        fixtures.op_capi_get_customer_by_id
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_valid_capi_create_binding{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.customer_access_token_valid,
        fixtures.op_capi_create_binding
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_valid_capi_get_binding{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.customer_access_token_valid,
        fixtures.op_capi_get_binding
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_customer_access_token_valid_capi_get_customer_events{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.customer_access_token_valid,
        fixtures.op_capi_get_customer_events
    ])
    not result.forbidden
    count(result.allowed) == 1
}
