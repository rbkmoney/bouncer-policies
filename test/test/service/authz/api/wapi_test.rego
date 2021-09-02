package test.service.authz.api.wapi

import data.service.authz.api
import data.test.service.authz.util
import data.test.service.authz.fixtures.context

wapi_public_operation_session_token_ctx = util.deepmerge([
    context.env_default,
    context.requester_default,
    context.user_administrator,
    context.session_token_valid,
    context.op_wapi_empty
])

test_get_residence_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetResidence"}
}

test_get_currency_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetCurrency"}
}

test_list_providers_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "ListProviders"}
}

test_get_provider_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetProvider"}
}

test_list_provider_identity_classes_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "ListProviderIdentityClasses"}
}

test_get_provider_identity_class_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetProviderIdentityClass"}
}

test_list_provider_identity_levels_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "ListProviderIdentityLevels"}
}

test_get_provider_identity_level_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : "GetProviderIdentityLevel"}
}

discretionary_op_with_common_cases(opId) {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : opId}
    util.is_forbidden with input as wapi_public_operation_session_token_ctx with input.wapi.op as {"id" : opId, "identity" : "SomeId"}
    util.is_allowed with input as wapi_public_operation_session_token_ctx
        with input.wapi.op as {"id" : opId, "identity" : "IdentityId"}
        with input.wallet as context.wallet_pool_with_identity.wallet
}

test_list_withdrawals_allowed {
    discretionary_op_with_common_cases("ListWithdrawals")
}

test_list_wallets_allowed {
    discretionary_op_with_common_cases("ListWallets")
}

test_list_destinations_allowed {
    discretionary_op_with_common_cases("ListDestinations")
}

test_list_deposits_allowed {
    discretionary_op_with_common_cases("ListDeposits")
}

test_list_deposit_reverts_allowed {
    discretionary_op_with_common_cases("ListDepositReverts")
}

test_list_deposit_adjustments_allowed {
    discretionary_op_with_common_cases("ListDepositAdjustments")
}

test_create_identity_with_invalid_auth_method_forbidden {
    util.is_forbidden with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.api_key_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {
        "id" : "CreateIdentity",
        "party" : "PARTY"
    }
}

test_create_identity_by_owner_allowed {
    util.is_allowed with input as util.deepmerge([
        context.env_default,
        context.requester_default,
        context.user_owner,
        context.session_token_valid,
        context.op_wapi_empty
    ]) with input.wapi.op as {
        "id" : "CreateIdentity",
        "party" : "PARTY"
    }
}

test_create_identity_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateIdentity",
        "party" : "PARTY"
    }
}

test_list_identities_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "ListIdentities",
        "party" : "PARTY"
    }
}

test_create_report_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateReport",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_create_webhook_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWebhook",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_create_wallet_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWallet",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_create_wallet_forbidden_with_undefined_op_name {
    util.is_forbidden with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWallet"
    }
    with input.wallet as []
}

test_create_destination_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateDestination",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_get_identity_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetIdentity",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_list_identity_challenges_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "ListIdentityChallenges",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_start_identity_challenge_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "StartIdentityChallenge",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_get_identity_challenge_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetIdentityChallenge",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_poll_identity_challenge_events_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "PollIdentityChallengeEvents",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_get_identity_challenge_event_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetIdentityChallengeEvent",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_get_webhooks_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWebhooks",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_get_reports_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetReports",
        "identity" : "IdentityId"
    }
    with input.wallet as context.wallet_pool_with_identity.wallet
}

test_create_w2w_transfer_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateW2WTransfer",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_get_wallet_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWallet",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_get_wallet_by_external_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWalletByExternalID",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_get_wallet_account_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWalletAccount",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_issue_wallet_grant_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "IssueWalletGrant",
        "wallet" : "WalletId"
    }
    with input.wallet as context.wallet_pool_with_wallet.wallet
}

test_create_quote_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateQuote",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

test_create_withdrawal_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "CreateWithdrawal",
        "wallet" : "WalletId",
        "destination" : "DestinationId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_wallet.wallet,
        context.wallet_pool_with_destination.wallet
    ])
}

test_get_destination_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetDestination",
        "destination" : "DestinationId"
    }
    with input.wallet as context.wallet_pool_with_destination.wallet
}

test_get_destination_by_external_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetDestinationByExternalID",
        "destination" : "DestinationId"
    }
    with input.wallet as context.wallet_pool_with_destination.wallet
}

test_issue_destination_grant_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "IssueDestinationGrant",
        "destination" : "DestinationId"
    }
    with input.wallet as context.wallet_pool_with_destination.wallet
}

test_get_withdrawal_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWithdrawal",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_get_withdrawal_by_external_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWithdrawalByExternalID",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_poll_withdrawal_events_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "PollWithdrawalEvents",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_get_withdrawal_events_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWithdrawalEvents",
        "withdrawal" : "WithdrawalId"
    }
    with input.wallet as context.wallet_pool_with_withdrawal.wallet
}

test_get_w2w_transfer_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetW2WTransfer",
        "w2w_transfer" : "W2WTransferId"
    }
    with input.wallet as context.wallet_pool_with_w2w_transfer.wallet
}

test_get_webhook_by_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetWebhookByID",
        "webhook" : "WebhookId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_identity.wallet,
        context.wallet_pool_with_webhook.wallet
    ])
}

test_delete_webhook_by_id_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "DeleteWebhookByID",
        "webhook" : "WebhookId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_identity.wallet,
        context.wallet_pool_with_webhook.wallet
    ])
}

test_get_report_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx with input.wapi.op as {
        "id" : "GetReport",
        "report" : "ReportId"
    }
    with input.wallet as util.concat([
        context.wallet_pool_with_identity.wallet,
        context.wallet_pool_with_report.wallet
    ])
}

test_create_w2w_transfer_with_wallet_grant_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx
        with input.wapi.op as {
            "id" : "CreateW2WTransfer",
            "wallet" : "WalletId"
        }
        with input.wapi.grants as context.wapi_wallet_grant.wapi.grants
        with input.wallet as context.wallet_pool_with_another_wallet.wallet
}

test_get_destination_with_destination_grant_allowed {
    util.is_allowed with input as wapi_public_operation_session_token_ctx
        with input.wapi.op as {
            "id" : "GetDestination",
            "destination" : "DestinationId"
        }
        with input.wapi.grants as context.wapi_destination_grant.wapi.grants
}
