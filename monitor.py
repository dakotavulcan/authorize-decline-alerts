import os
import json
import hmac
import hashlib
import urllib.request
import urllib.error
from decimal import Decimal, InvalidOperation

AUTHNET_URL = "https://api.authorize.net/xml/v1/request.api"
STATE_FILE = ".state.json"
STATE_CHANGED_FILE = ".state_changed"

API_LOGIN_ID = os.environ.get("AUTHNET_API_LOGIN_ID", "")
TRANSACTION_KEY = os.environ.get("AUTHNET_TRANSACTION_KEY", "")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
STATE_KEY = os.environ.get("STATE_ENCRYPTION_KEY", "")
RUN_MODE = os.environ.get("RUN_MODE", "live").strip().lower()

COMMON_DECLINES = {
    "2": (
        "General bank/issuer decline",
        "Try the card again, use another payment method, or have the customer contact the card issuer."
    ),
    "3": (
        "Issuer referral",
        "Have the customer contact the card issuer or use another payment method."
    ),
    "4": (
        "Card issuer decline",
        "Use another payment method and have the customer contact the card issuer."
    ),
    "27": (
        "Billing address mismatch (AVS)",
        "Verify the billing street address and ZIP/postal code exactly as the card issuer has them."
    ),
    "44": (
        "Card security code (CVV) mismatch",
        "Verify the 3- or 4-digit security code. If it still fails, use another payment method or contact the issuer."
    ),
    "45": (
        "Billing address and card security code mismatch",
        "Verify both the billing address/ZIP and the card security code before retrying."
    ),
    "65": (
        "Card security code (CVV) mismatch",
        "Verify the security code. The merchant's Card Code settings may be configured to decline this result."
    ),
    "250": (
        "Fraud filter blocked the transaction",
        "Review the transaction and Fraud Detection Suite settings in Authorize.Net before retrying."
    ),
    "251": (
        "Fraud Detection Suite filter decline",
        "Review the triggered fraud filter in Authorize.Net before asking the customer to retry."
    ),
    "254": (
        "Declined after fraud review",
        "Review the transaction in Authorize.Net for the fraud-review details."
    ),
    "315": (
        "Invalid card number",
        "Have the customer re-enter the card number or use another payment method."
    ),
    "316": (
        "Invalid expiration date",
        "Have the customer verify the card expiration date."
    ),
    "317": (
        "Expired card",
        "Have the customer use a current card or another payment method."
    ),
    "318": (
        "Duplicate transaction",
        "Check for a recent matching payment before trying the transaction again."
    ),
}


def require_secrets():
    if not all([
        API_LOGIN_ID,
        TRANSACTION_KEY,
        SLACK_WEBHOOK_URL,
        STATE_KEY
    ]):
        raise RuntimeError("A required GitHub secret is missing.")


def auth():
    return {
        "name": API_LOGIN_ID,
        "transactionKey": TRANSACTION_KEY
    }


def http_post(url, payload, slack=False):
    request = urllib.request.Request(
        url,
        data=json.dumps(
            payload,
            separators=(",", ":")
        ).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "authorize-decline-alerts/1.0"
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=30
        ) as response:
            raw = response.read().decode("utf-8-sig")

    except urllib.error.HTTPError:
        if slack:
            raise RuntimeError("Slack rejected the alert.")
        raise RuntimeError(
            "Authorize.Net returned an HTTP error."
        )

    except urllib.error.URLError:
        if slack:
            raise RuntimeError("Could not reach Slack.")
        raise RuntimeError(
            "Could not reach Authorize.Net."
        )

    if slack:
        return raw

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise RuntimeError(
            "Authorize.Net returned an unreadable response."
        )

    messages = data.get("messages") or {}

    if messages.get("resultCode") != "Ok":
        raise RuntimeError(
            "Authorize.Net returned an API error."
        )

    return data


def get_unsettled():
    payload = {
        "getUnsettledTransactionListRequest": {
            "merchantAuthentication": auth(),
            "status": "any",
            "sorting": {
                "orderBy": "submitTimeUTC",
                "orderDescending": True
            },
            "paging": {
                "limit": 1000,
                "offset": 1
            }
        }
    }

    data = http_post(
        AUTHNET_URL,
        payload
    )

    transactions = data.get(
        "transactions"
    ) or []

    if isinstance(transactions, dict):
        transactions = transactions.get(
            "transaction"
        ) or []

    if not isinstance(transactions, list):
        raise RuntimeError(
            "Authorize.Net returned an unexpected transaction list."
        )

    return transactions


def get_details(trans_id):
    payload = {
        "getTransactionDetailsRequest": {
            "merchantAuthentication": auth(),
            "transId": str(trans_id)
        }
    }

    data = http_post(
        AUTHNET_URL,
        payload
    )

    details = data.get("transaction")

    if not isinstance(details, dict):
        raise RuntimeError(
            "Authorize.Net returned unexpected transaction details."
        )

    return details


def fingerprint(trans_id):
    return hmac.new(
        STATE_KEY.encode(),
        str(trans_id).encode(),
        hashlib.sha256
    ).hexdigest()


def load_state():
    if not os.path.exists(STATE_FILE):
        return None

    try:
        with open(
            STATE_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            data = json.load(file)

        seen = data.get(
            "seen",
            []
        )

        if not isinstance(seen, list):
            raise ValueError

        return seen

    except (
        OSError,
        ValueError,
        json.JSONDecodeError
    ):
        raise RuntimeError(
            "The private monitor state could not be read."
        )


def save_state(seen):
    # Only anonymous fingerprints are stored.
    # No real transaction IDs or customer data.

    seen = list(
        dict.fromkeys(seen)
    )

    with open(
        STATE_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            {
                "version": 1,
                "seen": seen
            },
            file,
            separators=(",", ":")
        )

    with open(
        STATE_CHANGED_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        file.write("1")


def first_value(*values):
    for value in values:
        if value is not None and value != "":
            return value

    return None


def money(value):
    try:
        return (
            f"${Decimal(str(value)):,.2f}"
        )

    except (
        InvalidOperation,
        ValueError,
        TypeError
    ):
        return "Unknown"


def slack_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def explanation(details):
    code = str(
        details.get(
            "responseReasonCode"
        ) or ""
    ).strip()

    api_text = str(
        details.get(
            "responseReasonDescription"
        ) or "This transaction was declined."
    ).strip()

    plain, action = COMMON_DECLINES.get(
        code,
        (
            api_text,
            "Review the Authorize.Net transaction details. "
            "If the reason is not specific, have the customer "
            "contact the issuer or use another payment method."
        )
    )

    return (
        code or "Unknown",
        api_text,
        plain,
        action
    )


def build_message(
    summary,
    details,
    test=False
):

    trans_id = first_value(
        details.get("transId"),
        summary.get("transId"),
        "Unknown"
    )

    first_name = str(
        summary.get(
            "firstName"
        ) or ""
    ).strip()

    last_name = str(
        summary.get(
            "lastName"
        ) or ""
    ).strip()

    name = " ".join(
        part
        for part in [
            first_name,
            last_name
        ]
        if part
    ) or "Not provided"

    amount = first_value(
        details.get("authAmount"),
        details.get("requestedAmount"),
        summary.get("settleAmount")
    )

    card_type = (
        summary.get("accountType")
        or "Card"
    )

    masked = (
        summary.get("accountNumber")
        or "masked"
    )

    invoice = str(
        summary.get(
            "invoiceNumber"
        ) or ""
    ).strip()

    (
        code,
        api_text,
        plain,
        action
    ) = explanation(details)

    if test:
        heading = (
            "🧪 *TEST — PAYMENT DECLINED*"
        )
    else:
        heading = (
            "🚨 *PAYMENT DECLINED*"
        )

    lines = [
        heading,
        (
            f"*Customer:* "
            f"{slack_escape(name)}"
        ),
        (
            f"*Amount:* "
            f"{slack_escape(money(amount))}"
        ),
        (
            f"*Card:* "
            f"{slack_escape(card_type)} "
            f"{slack_escape(masked)}"
        ),
        (
            f"*Transaction ID:* "
            f"`{slack_escape(trans_id)}`"
        ),
        (
            f"*Reason Code:* "
            f"`{slack_escape(code)}`"
        )
    ]

    if invoice:
        lines.append(
            f"*Invoice / Order:* "
            f"{slack_escape(invoice)}"
        )

    lines += [
        "",
        (
            f"*What happened:* "
            f"{slack_escape(plain)}"
        ),
        (
            f"*Authorize.Net:* "
            f"{slack_escape(api_text)}"
        ),
        (
            f"*Recommended action:* "
            f"{slack_escape(action)}"
        )
    ]

    return {
        "text": "\n".join(lines)
    }


def send_slack(payload):
    http_post(
        SLACK_WEBHOOK_URL,
        payload,
        slack=True
    )


def main():
    require_secrets()

    transactions = get_unsettled()

    declines = [
        transaction
        for transaction in transactions
        if (
            str(
                transaction.get(
                    "transactionStatus"
                ) or ""
            ).lower()
            == "declined"
            and transaction.get("transId")
        )
    ]

    declines.sort(
        key=lambda transaction:
        str(
            transaction.get(
                "submitTimeUTC"
            ) or ""
        )
    )

    # TEST MODE:
    # Sends the most recent real decline
    # to Slack with a TEST heading.
    if RUN_MODE == "test_latest_decline":

        if declines:

            summary = declines[-1]

            details = get_details(
                summary["transId"]
            )

            send_slack(
                build_message(
                    summary,
                    details,
                    test=True
                )
            )

        else:

            send_slack({
                "text":
                "🧪 Authorize.Net decline monitor "
                "is connected. No current declined "
                "transaction was available to preview."
            })

        print("Test completed.")
        return

    seen = load_state()

    # FIRST RUN / BOOTSTRAP:
    # Remember existing declines without
    # sending historical Slack alerts.
    if (
        seen is None
        or RUN_MODE == "bootstrap"
    ):

        save_state([
            fingerprint(
                transaction["transId"]
            )
            for transaction
            in declines
        ])

        print("Baseline initialized.")
        return

    if RUN_MODE != "live":
        raise RuntimeError(
            "Unknown run mode."
        )

    seen_set = set(seen)
    changed = False

    for summary in declines:

        trans_id = str(
            summary["transId"]
        )

        transaction_fingerprint = (
            fingerprint(trans_id)
        )

        if (
            transaction_fingerprint
            in seen_set
        ):
            continue

        details = get_details(
            trans_id
        )

        send_slack(
            build_message(
                summary,
                details
            )
        )

        # Only remember it AFTER Slack
        # successfully accepts the alert.

        seen.append(
            transaction_fingerprint
        )

        seen_set.add(
            transaction_fingerprint
        )

        changed = True

    if changed:
        save_state(seen)

    print("Check completed.")


if __name__ == "__main__":
    main()
