package service.authz.api.capi.payment_tool

import input.capi.op
import input.payment_tool

forbidden[why] {
    payment_tool.expiration
    exp := time.parse_rfc3339_ns(payment_tool.expiration)
    now := time.parse_rfc3339_ns(input.env.now)
    now > exp
    why := {
        "code": "payment_tool_expired",
        "description": sprintf("Payment tool expired at: %s", [payment_tool.expiration])
    }
}

forbidden[why] {
    op.id == "CreatePaymentResource"
    payment_tool.scope[_]
    not shop_matches_token_scope
    why := {
        "code": "payment_tool_forbidden",
        "description": "Provider payment tool forbidden payment resource tokenization"
    }
}

forbidden[why] {
    op.id == "CreatePayment"
    payment_tool.scope[_]
    op.invoice.id != payment_tool.scope.invoice.id
    why := {
        "code": "payment_tool_forbidden",
        "description": "Payment resource forbidden this invoice"
    }
}

forbidden[why] {
    op.id == "CreateBinding"
    payment_tool.scope[_]
    op.customer.id != payment_tool.scope.customer.id
    why := {
        "code": "payment_tool_forbidden",
        "description": "Payment resource forbidden this customer"
    }
}

shop_matches_token_scope {
    scope := input.auth.scope[_]
    scope.shop.id == payment_tool.scope.shop.id
    scope.party.id == payment_tool.scope.party.id
}
