package test.service.authz.api.url_shortener

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

test_session_token_valid_shortener_shorten_url{
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_shortener_shorten_url
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_session_token_valid_shortener_delete_shorten_url {
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_shortener_delete_shorten_url
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_session_token_valid_shortener_get_shorten_url{
    result := api.assertions with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_default,
        context.session_token_valid,
        context.op_shortener_get_shorten_url
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}
