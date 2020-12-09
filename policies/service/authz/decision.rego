package service.authz.decision

import data.service.authz.api

decide(assertions) = d {
    count(assertions.forbidden) > 0
    d := {
        "verdict": ["forbidden", assertions.forbidden]
    }
}

decide(assertions) = d {
    count(assertions.forbidden) == 0
    assertions.restrictions != {}
    count(assertions.allowed) > 0
    d := {
        "verdict": ["restricted", assertions.allowed],
        "restrictions": assertions.restrictions
    }
}

decide(assertions) = d {
    count(assertions.forbidden) == 0
    assertions.restrictions == {}
    count(assertions.allowed) > 0
    d := {
        "verdict": ["allowed", assertions.allowed]
    }
}

decide(assertions) = d {
    count(assertions.forbidden) == 0
    count(assertions.allowed) == 0
    d := {
        "verdict": ["forbidden", []]
    }
}
