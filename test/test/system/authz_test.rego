package test.system.authz

import data.system.authz

test_empty_context_forbidden {
    result := authz.allow with input as {}
    result == false
}

test_post_data_allowed {
    authz.allow with input as {
        "path" : [
            "v1",
            "data",
            "service"
        ],
        "method" : "POST"
    }
}

test_get_data_allowed {
    authz.allow with input as {
        "path" : [
            "v1",
            "data",
            "service"
        ],
        "method" : "GET"
    }
}

test_get_policies_allowed {
    authz.allow with input as {
        "path" : [
            "v1",
            "policies"
        ],
        "method" : "GET"
    }
}

test_health_allowed {
    authz.allow with input as {
        "path" : [
            "health"
        ],
        "method" : "GET"
    }
}

test_metrics_allowed {
    authz.allow with input as {
        "path" : [
            "metrics"
        ],
        "method" : "GET"
    }
}
