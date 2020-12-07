package service.authz.decision

import data.service.authz.api

decision = d {
    assertions := api.assertions
    count(assertions.forbidden) > 0
    d := ["forbidden", assertions.forbidden]
}

decision = d {
    assertions := api.assertions
    count(assertions.forbidden) == 0
    count(assertions.allowed) > 0
    d := ["allowed", assertions.allowed]
}

decision = d {
    assertions := api.assertions
    count(assertions.forbidden) == 0
    count(assertions.allowed) == 0
    d := ["forbidden", []]
}
