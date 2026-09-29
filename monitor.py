import os
import json
import hmac
import hashlib
import urllib.request
import urllib.error
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from zoneinfo import ZoneInfo


# ============================================================
# CONFIGURATION
# ============================================================

AUTHNET_URL = "https://api.authorize.net/xml/v1/request.api"

STATE_FILE = ".state.json"
STATE_CHANGED_FILE = ".state_changed"

API_LOGIN_ID = os.environ.get(
    "AUTHNET_API_LOGIN_ID",
    ""
).strip()

TRANSACTION_KEY = os.environ.get(
    "AUTHNET_TRANSACTION_KEY",
    ""
).strip()

SLACK_WEBHOOK_URL = os.environ.get(
    "SLACK_WEBHOOK_URL",
    ""
).strip()

STATE_KEY = os.environ.get(
    "STATE_ENCRYPTION_KEY",
    ""
).strip()

TARGET_SOLUTION_NAME = os.environ.get(
    "TARGET_SOLUTION_NAME",
    ""
).strip()

RUN_MODE = os.environ.get(
    "RUN_MODE",
    "live"
).strip().lower()

EASTERN_TZ = ZoneInfo("America/New_York")


# ============================================================
# FRIENDLY DECLINE EXPLANATIONS
# ============================================================

COMMON_DECLINES = {
    "2": (
        "General bank/issuer decline",
        "Try the card again, use another payment method, "
        "or have the customer contact their card issuer."
    ),

    "3": (
        "Issuer referral",
        "Have the customer contact their card issuer or "
        "use another payment method."
    ),

    "4": (
        "Card issuer decline",
        "Use another payment method and have the customer "
        "contact their card issuer."
    ),

    "27": (
        "Billing address mismatch (AVS)",
        "Verify the billing street address and ZIP/postal code "
        "exactly as the card issuer has them."
    ),

    "44": (
        "Card security code (CVV) mismatch",
        "Verify the 3- or 4-digit security code. If it still "
        "fails, use another payment method or contact the issuer."
    ),

    "45": (
        "Billing address and card security code mismatch",
        "Verify both the billing address/ZIP and the card "
        "security code before retrying."
    ),

    "65": (
        "Card security code (CVV) mismatch",
        "Verify the security code. The merchant's Card Code "
        "settings may also be configured to decline this result."
    ),

    "250": (
        "Fraud filter blocked the transaction",
        "Review the transaction and Fraud Detection Suite "
        "settings in Authorize.Net before retrying."
    ),

    "251": (
        "Fraud Detection Suite filter decline",
        "Review the triggered fraud filter in Authorize.Net "
        "before asking the customer to retry."
    ),

    "254": (
        "Declined after fraud review",
        "Review the transaction in Authorize.Net for the "
        "fraud-review details."
    ),

    "315": (
        "Invalid card number",
        "Have the customer re-enter the card number or use "
        "another payment method."
    ),

    "316": (
        "Invalid expiration date",
        "Have the customer verify the card expiration date."
    ),

    "317": (
        "Expired card",
        "Have the customer use a current card or another "
        "payment method."
    ),

    "318": (
        "Duplicate transaction",
        "Check for a recent matching payment before trying "
        "the transaction again."
    ),
}


# ============================================================
# VERIFY REQUIRED GITHUB SECRETS
# ============================================================

def require_secrets():

    required = [
        API_LOGIN_ID,
        TRANSACTION_KEY,
        SLACK_WEBHOOK_URL,
        STATE_KEY,
        TARGET_SOLUTION_NAME,
    ]

    if not all(required):
        raise RuntimeError(
            "A required GitHub secret is missing."
        )


# ============================================================
# AUTHORIZE.NET AUTHENTICATION
# ============================================================

def auth():

    return {
        "name": API_LOGIN_ID,
        "transactionKey": TRANSACTION_KEY,
    }


# ============================================================
# HTTP REQUEST
# ============================================================

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
            "User-Agent": "authorize-decline-alerts/1.0",
        },
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=30
        ) as response:

            raw = response.read().decode(
                "utf-8-sig"
            )

    except urllib.error.HTTPError:

        if slack:
            raise RuntimeError(
                "Slack rejected the alert."
            )

        raise RuntimeError(
            "Authorize.Net returned an HTTP error."
        )

    except urllib.error.URLError:

        if slack:
            raise RuntimeError(
                "Could not reach Slack."
            )

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


# ============================================================
# GET CURRENT UNSETTLED TRANSACTIONS
# ============================================================

def get_unsettled():

    payload = {
        "getUnsettledTransactionListRequest": {
            "merchantAuthentication": auth(),

            "status": "any",

            "sorting": {
                "orderBy": "submitTimeUTC",
                "orderDescending": True,
            },

            "paging": {
                "limit": 1000,
                "offset": 1,
            },
        }
    }

    data = http_post(
        AUTHNET_URL,
        payload
    )

    transactions = (
        data.get("transactions")
        or []
    )

    if isinstance(transactions, dict):

        transactions = (
            transactions.get("transaction")
            or []
        )

    if not isinstance(transactions, list):

        raise RuntimeError(
            "Authorize.Net returned an unexpected "
            "transaction list."
        )

    return transactions


# ============================================================
# GET FULL DETAILS FOR ONE TRANSACTION
# ============================================================

def get_details(trans_id):

    payload = {
        "getTransactionDetailsRequest": {
            "merchantAuthentication": auth(),
            "transId": str(trans_id),
        }
    }

    data = http_post(
        AUTHNET_URL,
        payload
    )

    details = data.get("transaction")

    if not isinstance(details, dict):

        raise RuntimeError(
            "Authorize.Net returned unexpected "
            "transaction details."
        )

    return details


# ============================================================
# SOLUTION / SOURCE FILTER
# ============================================================

def get_solution_name(details):

    solution = details.get("solution") or {}

    if not isinstance(solution, dict):
        return ""

    return str(
        solution.get("name")
        or ""
    ).strip()


def is_target_solution(details):

    actual_solution = (
        get_solution_name(details)
    )

    if not actual_solution:
        return False

    return (
        actual_solution.casefold()
        ==
        TARGET_SOLUTION_NAME.casefold()
    )


# ============================================================
# PRIVATE TRANSACTION FINGERPRINT
# ============================================================

def fingerprint(trans_id):

    return hmac.new(
        STATE_KEY.encode("utf-8"),
        str(trans_id).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ============================================================
# LOAD PRIVATE STATE
# ============================================================

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
        json.JSONDecodeError,
    ):

        raise RuntimeError(
            "The private monitor state could not be read."
        )


# ============================================================
# SAVE PRIVATE STATE
# ============================================================

def save_state(seen):

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
                "seen": seen,
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


# ============================================================
# GENERAL HELPERS
# ============================================================

def first_value(*values):

    for value in values:

        if (
            value is not None
            and value != ""
        ):
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
        TypeError,
    ):

        return "Unknown"


def slack_escape(value):

    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ============================================================
# DATE / TIME HELPERS
# ============================================================

def parse_utc_time(value):

    if not value:
        return None

    text = str(value).strip()

    try:

        parsed = datetime.fromisoformat(
            text.replace(
                "Z",
                "+00:00"
            )
        )

        if parsed.tzinfo is None:

            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed.astimezone(
            timezone.utc
        )

    except ValueError:

        return None


def format_eastern(dt):

    local = dt.astimezone(
        EASTERN_TZ
    )

    date_text = local.strftime(
        "%a %b %d, %Y"
    ).replace(
        " 0",
        " "
    )

    time_text = local.strftime(
        "%I:%M %p"
    ).lstrip("0")

    return (
        f"{date_text} "
        f"{time_text} "
        f"{local.tzname()}"
    )


def format_delay(seconds):

    total_minutes = max(
        0,
        int(seconds // 60)
    )

    days, remainder = divmod(
        total_minutes,
        1440
    )

    hours, minutes = divmod(
        remainder,
        60
    )

    parts = []

    if days:

        parts.append(
            f"{days}d"
        )

    if hours:

        parts.append(
            f"{hours}h"
        )

    if minutes or not parts:

        parts.append(
            f"{minutes}m"
        )

    return " ".join(parts)


# ============================================================
# TRANSLATE DECLINE REASON
# ============================================================

def explanation(details):

    code = str(
        details.get(
            "responseReasonCode"
        )
        or ""
    ).strip()

    api_text = str(
        details.get(
            "responseReasonDescription"
        )
        or "This transaction was declined."
    ).strip()

    plain, action = COMMON_DECLINES.get(
        code,
        (
            api_text,

            "Review the Authorize.Net transaction details. "
            "If the reason is not specific, have the customer "
            "contact their card issuer or use another payment "
            "method."
        )
    )

    return (
        code or "Unknown",
        api_text,
        plain,
        action,
    )


# ============================================================
# BUILD SLACK MESSAGE
# ============================================================

def build_message(
    summary,
    details,
    test=False
):

    trans_id = first_value(
        details.get("transId"),
        summary.get("transId"),
        "Unknown",
    )

    first_name = str(
        summary.get("firstName")
        or ""
    ).strip()

    last_name = str(
        summary.get("lastName")
        or ""
    ).strip()

    name = " ".join(
        part
        for part in [
            first_name,
            last_name,
        ]
        if part
    )

    if not name:
        name = "Not provided"

    amount = first_value(
        details.get("authAmount"),
        details.get("requestedAmount"),
        summary.get("settleAmount"),
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
        summary.get("invoiceNumber")
        or ""
    ).strip()

    solution_name = (
        get_solution_name(details)
        or "Unknown"
    )

    submitted_at = parse_utc_time(
        first_value(
            summary.get("submitTimeUTC"),
            details.get("submitTimeUTC"),
        )
    )

    picked_up_at = datetime.now(
        timezone.utc
    )

    (
        code,
        api_text,
        plain,
        action,
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
        ),

        (
            f"*Source:* "
            f"{slack_escape(solution_name)}"
        ),
    ]

    # --------------------------------------------------------
    # TRANSACTION / PICKUP TIMES
    # --------------------------------------------------------

    if submitted_at:

        lines.append(
            (
                f"*Transaction time:* "
                f"{slack_escape(format_eastern(submitted_at))}"
            )
        )

        lines.append(
            (
                f"*Picked up:* "
                f"{slack_escape(format_eastern(picked_up_at))}"
            )
        )

        delay_seconds = (
            picked_up_at
            - submitted_at
        ).total_seconds()

        # If the transaction is 10+ minutes old,
        # clearly flag that this was a delayed pickup.
        #
        # This is especially useful for:
        # - overnight declines
        # - after-hours declines
        # - weekend declines
        # - a temporarily delayed GitHub runner

        if delay_seconds >= 600:

            lines.append(
                (
                    f"⏰ *Delayed pickup:* "
                    f"{slack_escape(format_delay(delay_seconds))} "
                    f"after the transaction occurred."
                )
            )

    if invoice:

        lines.append(
            (
                f"*Invoice / Order:* "
                f"{slack_escape(invoice)}"
            )
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
        ),
    ]

    return {
        "text": "\n".join(lines)
    }


# ============================================================
# SEND TO SLACK
# ============================================================

def send_slack(payload):

    http_post(
        SLACK_WEBHOOK_URL,
        payload,
        slack=True,
    )


# ============================================================
# MAIN MONITOR
# ============================================================

def main():

    require_secrets()

    transactions = get_unsettled()

    # First narrow the Authorize.Net list
    # down to actual declined transactions.

    declines = [
        transaction

        for transaction in transactions

        if (
            str(
                transaction.get(
                    "transactionStatus"
                )
                or ""
            ).lower()
            == "declined"

            and transaction.get(
                "transId"
            )
        )
    ]

    # Process oldest -> newest.
    #
    # This is important when several declines occurred
    # overnight or over the weekend. Slack will receive
    # them in chronological order.

    declines.sort(
        key=lambda transaction:
        str(
            transaction.get(
                "submitTimeUTC"
            )
            or ""
        )
    )


    # ========================================================
    # TEST MODE
    # ========================================================
    #
    # Finds the newest declined transaction specifically
    # from the configured solution (Jotform Live).
    #
    # Test mode DOES NOT add it to the seen list.
    # ========================================================

    if RUN_MODE == "test_latest_decline":

        matching_summary = None
        matching_details = None

        for summary in reversed(
            declines
        ):

            details = get_details(
                summary["transId"]
            )

            if is_target_solution(
                details
            ):

                matching_summary = summary
                matching_details = details
                break

        if (
            matching_summary
            and matching_details
        ):

            send_slack(
                build_message(
                    matching_summary,
                    matching_details,
                    test=True,
                )
            )

        else:

            send_slack({
                "text":
                    "🧪 Authorize.Net decline monitor "
                    "is connected, but no current "
                    "declined transaction from the "
                    "configured payment solution was "
                    "available to preview."
            })

        print(
            "Test completed."
        )

        return


    # ========================================================
    # LOAD EXISTING HISTORY
    # ========================================================

    seen = load_state()


    # ========================================================
    # BOOTSTRAP MODE
    # ========================================================
    #
    # Everything currently declined is considered OLD.
    #
    # Do not use this during normal operation.
    # ========================================================

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

        print(
            "Baseline initialized."
        )

        return


    # ========================================================
    # ONLY LIVE IS VALID FROM THIS POINT
    # ========================================================

    if RUN_MODE != "live":

        raise RuntimeError(
            "Unknown run mode."
        )


    seen_set = set(seen)

    changed = False


    # ========================================================
    # PROCESS NEW DECLINES
    # ========================================================

    for summary in declines:

        trans_id = str(
            summary["transId"]
        )

        transaction_fingerprint = (
            fingerprint(trans_id)
        )


        # ----------------------------------------------------
        # ALREADY PROCESSED
        # ----------------------------------------------------

        if (
            transaction_fingerprint
            in seen_set
        ):

            continue


        # ----------------------------------------------------
        # GET FULL AUTHORIZE.NET DETAILS
        # ----------------------------------------------------

        details = get_details(
            trans_id
        )


        # ----------------------------------------------------
        # ONLY SEND TARGET SOLUTION TO SLACK
        # ----------------------------------------------------

        if is_target_solution(
            details
        ):

            send_slack(
                build_message(
                    summary,
                    details,
                )
            )


        # ----------------------------------------------------
        # REMEMBER THE TRANSACTION
        # ----------------------------------------------------
        #
        # We remember BOTH:
        #
        # - Jotform Live declines
        # - Non-Jotform declines
        #
        # Non-Jotform declines are silently discarded once.
        #
        # Jotform declines are only marked processed after
        # Slack successfully accepted the alert.
        # ----------------------------------------------------

        seen.append(
            transaction_fingerprint
        )

        seen_set.add(
            transaction_fingerprint
        )

        changed = True


    # ========================================================
    # SAVE UPDATED STATE
    # ========================================================

    if changed:

        save_state(
            seen
        )


    print(
        "Check completed."
    )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    main()
