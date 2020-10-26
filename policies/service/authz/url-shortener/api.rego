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
     why := {
        "code": "ok",
        "description": "We can shorter url !)"
    }
}

operation_allowed
    { op.id == "ShortenUrl" }
    { op.id == "GetShortenedUrl" }
