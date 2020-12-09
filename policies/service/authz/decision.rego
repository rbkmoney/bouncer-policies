package service.authz.decision

import data.service.authz.api

decide(assertions) = d {
    count(assertions.forbidden) > 0
    d := ["forbidden", assertions.forbidden]
}

decide(assertions) = d {
    count(assertions.forbidden) == 0
    count(assertions.allowed) > 0
    d := ["allowed", assertions.allowed]
}

decide(assertions) = d {
    count(assertions.forbidden) == 0
    count(assertions.allowed) == 0
    d := ["forbidden", []]
}
