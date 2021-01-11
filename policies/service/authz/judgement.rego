package service.authz.judgement

judge(assertions) = jm {
    assertions.forbidden
    jm := {
        "resolution": ["forbidden", assertions.forbidden]
    }
}

judge(assertions) = jm {
    not assertions.forbidden
    assertions.restrictions
    assertions.allowed
    jm := {
        "resolution": ["restricted", assertions.allowed],
        "restrictions": assertions.restrictions
    }
}

judge(assertions) = jm {
    not assertions.forbidden
    not assertions.restrictions
    assertions.allowed
    jm := {
        "resolution": ["allowed", assertions.allowed]
    }
}

judge(assertions) = jm {
    not assertions.forbidden
    not assertions.allowed
    jm := {
        "resolution": ["forbidden", []]
    }
}
