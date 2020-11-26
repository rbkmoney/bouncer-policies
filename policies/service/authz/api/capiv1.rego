package service.authz.api.capiv1

import input.capi.op
import input.invoicing

allowed[why] {
    requires_invoicing_context
    input_matches_invoicing_context
    why := {
        "code": "session_token_allows_operation",
        "description": "Session token allows this operation"
    }
}


input_matches_invoicing_context {
    op.party.id == invoicing.party.id
    op.shop.id  == invoicing.shop.id
    op.invoice.id == invoicing.invoice.id
    op.payment.id == invoicing.payment.id
    # op.refund.id == invoicing.refund.id
}

requires_invoicing_context
    { op.id == "CreateInvoiceAccessToken" }
    { op.id == "FulfillInvoice" }
    { op.id == "RescindInvoice" }
    { op.id == "CancelPayment" }
    { op.id == "CapturePayment" }
    { op.id == "CreateRefund" }
    { op.id == "GetRefunds" }
    { op.id == "GetRefundByID" }
