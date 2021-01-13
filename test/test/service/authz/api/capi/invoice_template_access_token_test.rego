package test.service.authz.api.capi.invoice_template_access_token

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_invoice_template_access_token_valid_capi_get_invoice_template_by_id{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_template_access_token_valid,
        fixtures.op_capi_get_invoice_template_by_id
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_template_access_token_valid_capi_create_invoice_with_template{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_template_access_token_valid,
        fixtures.op_capi_create_invoice_with_template
    ])
    not result.forbidden
    count(result.allowed) == 1
}

test_invoice_template_access_token_valid_capi_get_invoice_payment_methods_by_template_id{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.invoice_template_access_token_valid,
        fixtures.op_capi_get_invoice_payment_methods_by_template_id
    ])
    not result.forbidden
    count(result.allowed) == 1
}
