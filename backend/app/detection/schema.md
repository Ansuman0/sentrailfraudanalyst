Unified transaction schema (bank, card and crypto all map to this):

txn_id, timestamp, customer_id, account_id, counterparty_id, direction (in/out),
amount, currency, channel (bank|card|crypto), country, merchant_category, is_laundering (training only)
