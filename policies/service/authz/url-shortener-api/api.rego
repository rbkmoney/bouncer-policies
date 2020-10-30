package service.authz.api.url_shortener

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be a 2-item array of the following form:
# ```
# ["code", "description"]
# ```

import input.shortener.op

allowed[why] {
    operation_allowed
    shortened_url_owner_matches_user_id
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows operation on this shortened url"
    }
}

allowed[why] {
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
