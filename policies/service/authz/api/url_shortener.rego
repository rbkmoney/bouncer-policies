package service.authz.api.url_shortener

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```

import input.shortener.op

allowed[why] {
    input.auth.method == "SessionToken"
    allowed_for_session_token[why]
}

allowed_for_session_token[why] {
    operation_allowed
    shortened_url_owner_matches_user_id
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows operation on this shortened url"
    }
}

allowed_for_session_token[why] {
    op.id == "ShortenUrl"
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}

shortened_url_owner_matches_user_id {
    input.user.id == op.shortened_url.owner.id
}

operation_allowed
    { op.id == "DeleteShortenedUrl" }
    { op.id == "GetShortenedUrl" }
