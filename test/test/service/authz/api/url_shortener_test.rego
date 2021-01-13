package test.service.authz.api.url_shortener

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures

test_session_token_valid_shortener_shorten_url{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_shortener_shorten_url
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_session_token_valid_shortener_delete_shorten_url {
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_shortener_delete_shorten_url
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}

test_session_token_valid_shortener_get_shorten_url{
    result := api.assertions with input as util.deepmerge([
        fixtures.env_default,
        fixtures.requester_default,
        fixtures.user_default,
        fixtures.session_token_valid,
        fixtures.op_shortener_get_shorten_url
    ])
    not result.forbidden
    count(result.allowed) == 1
    result.allowed[_].code == "session_token_allows_operation"
}
