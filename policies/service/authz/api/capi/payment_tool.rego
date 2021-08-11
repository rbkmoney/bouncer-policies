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
    payment_tool.scope.shop.id
    not pass_shop_scope
    why := {
        "code": "payment_tool_forbidden",
        "description": sprintf("Provider payment tool linked to shop: %s", [payment_tool.scope.shop.id])
    }
}

forbidden[why] {
    op.id == "CreatePayment"
    payment_tool.scope.invoice.id
    not pass_invoice_operation
    why := {
        "code": "payment_tool_forbidden",
        "description": sprintf("Payment tool is linked to invoice: %s", [payment_tool.scope.invoice.id])
    }
}

forbidden[why] {
    op.id == "CreateBinding"
    payment_tool.scope.customer.id
    not pass_customer_operation
    why := {
        "code": "payment_tool_forbidden",
        "description": sprintf("Payment tool is linked to customer: %s", [payment_tool.scope.customer.id])
    }
}

pass_shop_scope {
    scope := input.auth.scope[_]
    scope.shop.id == payment_tool.scope.shop.id
    scope.party.id == payment_tool.scope.party.id
}

pass_invoice_operation {
    op.invoice.id == payment_tool.scope.invoice.id
}

pass_customer_operation {
    op.customer.id == payment_tool.scope.customer.id
}
