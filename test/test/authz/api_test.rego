package test.authz.api

import data.service.authz.api
import data.test.authz.util
import data.test.authz.fixtures

test_no_warnings {
    count(api.warnings) == 0
}

test_empty_context_forbidden {
    result := api.assertions with input as {}
    result.forbidden[_].code == "auth_required"
}

test_token_blacklisted_local_ip {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_local,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    result.forbidden[_].code == "ip_range_blacklisted"
}

test_token_blacklisted_local_ipv6 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_local_ipv6,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    result.forbidden[_].code == "ip_range_blacklisted"
}

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

test_session_token_valid_operation_1 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_shortener_shorten_url
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_session_token_valid_operation_2 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_shortener_delete_shorten_url
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_session_token_valid_operation_3 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_owner,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "user_is_owner"
}

test_session_token_valid_operation_4 {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_capi_create_invoice
    ])
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "user_has_role"
}

test_lookup_card_info_allowed {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.session_token_valid,
        fixtures.op_binapi_lookup_card_info
    ]) with data.service.authz.whitelists.bin_lookup_allowed_party_ids as ["PARTY_2"]
    count(result.forbidden) == 0
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_lookup_card_info_forbidden {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.session_token_valid,
        fixtures.op_binapi_lookup_card_info
    ]) with data.service.authz.whitelists.bin_lookup_allowed_party_ids as ["PARTY_3"]
    count(result.forbidden) == 0
    count(result.allowed) == 0
}
