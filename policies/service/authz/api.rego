package service.authz.api

import data.service.authz.api.invoice_access_token
import data.service.authz.api.url_shortener
import data.service.authz.api.binapi
import data.service.authz.api.anapi
import data.service.authz.api.capi
import data.service.authz.api.orgmgmt
import data.service.authz.api.wapi
import data.service.authz.api.claimmgmt
import data.service.authz.blacklists
import data.service.authz.whitelists
import data.service.authz.roles
import data.service.authz.org
import data.service.authz.judgement
import data.service.authz.methods

assertions = a {
    a0 := {
        "forbidden" : { why | forbidden[why] },
        "allowed"   : { why | allowed[why] },
        "restrictions": { what.type: what.restrictions[what.type] | restrictions[what] }
    }
    a := { name: values | values := a0[name]; count(values) > 0 }
}

judgement := judgement.judge(assertions)

# Set of assertions which tell why operation under the input context is forbidden.
# When the set is empty operation is not explicitly forbidden.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```
forbidden[why] {
    input
    not input.auth.method
    why := {
        "code": "auth_required",
        "description": "Authorization is required"
    }
}

forbidden[why] {
    not known_auth_method
    why := {
        "code": "unknown_auth_method",
        "description": "Authorization method is unknown"
    }
}

forbidden[why] {
    not tolerate_no_expiration
    not input.auth.expiration
    why := {
        "code": "auth_no_token_expiration",
        "description": "Tokens without expiration are not allowed"
    }
}

forbidden[why] {
    not tolerate_expired_token
    exp := time.parse_rfc3339_ns(input.auth.expiration)
    now := time.parse_rfc3339_ns(input.env.now)
    now > exp
    why := {
        "code": "auth_expired",
        "description": sprintf("Authorization expired at: %s", [input.auth.expiration])
    }
}

forbidden[why] {
    ip := input.requester.ip
    blacklist := blacklists.source_ip_range.entries
    matches := net.cidr_contains_matches(blacklist, ip)
    matches[_]
    ranges := [ range | matches[_][0] = i; range := blacklist[i] ]
    why := {
        "code": "ip_range_blacklisted",
        "description": sprintf(
            "Requester IP address is blacklisted with ranges: %v",
            [concat(", ", ranges)]
        )
    }
}

forbidden[why] {
    not input.auth.token.id
    why := {
        "code": "auth_token_missing_id",
        "description": "Requester auth token is missing ID"
    }
}

forbidden[why] {
    token := input.auth.token
    blacklist := blacklists.auth_token.entries
    token.id == blacklist[_]
    why := {
        "code": "auth_token_blacklisted",
        "description": sprintf(
            "Requester auth token is blacklisted with id: %s",
            [token.id]
        )
    }
}

forbidden[why] {
    input.anapi
    anapi.forbidden[why]
}

forbidden[why] {
    input.capi
    capi.forbidden[why]
}

forbidden[why] {
    input.orgmgmt
    orgmgmt.forbidden[why]
}

forbidden[why] {
    input.wapi
    wapi.forbidden[why]
}

forbidden[why] {
    input.claimmgmt
    claimmgmt.forbidden[why]
}

known_auth_method {
    methods.methods[_] == input.auth.method
}

tolerate_no_expiration {
    input.auth.method == "ApiKeyToken"
}
tolerate_no_expiration {
    # Invoice template access tokens currently have unlimited(undefined) expiration
    input.auth.method == "InvoiceTemplateAccessToken"
}

tolerate_expired_token {
    input.capi
    input.auth.method == "SessionToken"
}

tolerate_expired_token {
    input.anapi
    input.auth.method == "SessionToken"
}

tolerate_expired_token {
    input.wapi
    input.auth.method == "SessionToken"
}

warnings[why] {
    not blacklists.source_ip_range.entries
    why := "Blacklist 'source_ip_range' is not defined, blacklisting by IP will NOT WORK."
}

warnings[why] {
    not blacklists.auth_token.entries
    why := "Blacklist 'auth_token' is not defined, blacklisting by specific JWTs will NOT WORK."
}

warnings[why] {
    not whitelists.binapi_party_ids.entries
    why := "Whitelist 'binapi_party_ids' is not defined, whitelisting by partyID will NOT WORK."
}

# Set of assertions which tell why operation under the input context is allowed.
# When the set is empty operation is not explicitly allowed.
# Each element must be an object of the following form:
# ```
# {"code": "auth_expired", "description": "..."}
# ```
allowed[why] {
    input.shortener
    url_shortener.allowed[why]
}

allowed[why] {
    input.binapi
    binapi.allowed[why]
}

allowed[why] {
    input.capi
    capi.allowed[why]
}

allowed[why] {
    input.anapi
    anapi.allowed[why]
}

allowed[why] {
    input.orgmgmt
    orgmgmt.allowed[why]
}

allowed[why] {
    input.wapi
    wapi.allowed[why]
}

allowed[why] {
    input.claimmgmt
    claimmgmt.allowed[why]
}

# Restrictions

restrictions[what] {
    input.anapi
    rstns := anapi.restrictions[_]
    what := {
        "type": "anapi",
        "restrictions": rstns
    }
}

restrictions[what] {
    input.capi
    rstns := capi.restrictions[_]
    what := {
        "type": "capi",
        "restrictions": rstns,
    }
}
