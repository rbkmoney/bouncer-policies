package test.authz.system

import data.system.authz

test_empty_context_forbidden {
    result := authz.allow with input as {}
    result == false
}

test_get_post_data_allowed {
    result := authz.allow with input as {
        "path" : [
            "v1",
            "data",
            "service"
        ],
        "method" : "POST"
    }
    result == true
}

test_get_policies_allowed {
    result := authz.allow with input as {
        "path" : [
            "v1",
            "policies"
        ],
        "method" : "GET"
    }
    result == true
}

test_health_allowed {
    result := authz.allow with input as {
        "path" : [
            "health"
        ],
        "method" : "GET"
    }
    result == true
}

test_metrics_allowed {
    result := authz.allow with input as {
        "path" : [
            "metrics"
        ],
        "method" : "GET"
    }
    result == true
}
