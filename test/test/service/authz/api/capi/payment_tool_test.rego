package test.service.authz.api.capi.payment_tool

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_allowed_payment_tool_unlinked {
  util.is_allowed with input as util.deepmerge([
      context.env_default,
      context.requester_default,
      context.api_key_token_valid,
      context.op_capi_create_payment,
      context.payproc_invoice,
      context.payment_tool_unlinked
  ])
}

test_allowed_payment_tool_provider {
  util.is_allowed with input as util.deepmerge([
      context.env_default,
      context.requester_default,
      context.invoice_access_token_valid,
      context.op_capi_create_payment_resource,
      context.payment_tool_shop
  ])
}

test_forbidden_payment_tool_expiration {
  result := api.assertions with input as util.deepmerge([
      context.env_default,
      context.op_capi_create_payment,
      context.payment_tool_expiration
  ])
  result.forbidden[_].code == "payment_tool_expired"
}

test_forbidden_payment_tool_provider {
  result := api.assertions with input as util.deepmerge([
      context.env_default,
      context.requester_default,
      context.invoice_access_token_valid,
      context.op_capi_create_payment_resource,
      context.payment_tool_shop2
  ])
  result.forbidden[_].code == "payment_tool_forbidden"
}

test_forbidden_payment_tool_invoice {
  result := api.assertions with input as util.deepmerge([
      context.env_default,
      context.requester_default,
      context.api_key_token_valid,
      context.op_capi_create_payment,
      context.payproc_invoice,
      context.payment_tool_invoice2
  ])
  result.forbidden[_].code == "payment_tool_forbidden"
}

test_forbidden_payment_tool_customer {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.api_key_token_valid,
        context.op_capi_create_binding,
        context.payproc_customer,
        context.payment_tool_customer2
    ])
    result.forbidden[_].code == "payment_tool_forbidden"
}
