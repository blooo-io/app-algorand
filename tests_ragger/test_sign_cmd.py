import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.navigator import NavInsID, Navigator

from .application_client.algorand_command_sender import AlgorandCommandSender, Errors
from .application_client.algorand_response_unpacker import (
    unpack_get_public_key_response,
)
from .utils import check_tx_signature_validity, encode_aprv_transaction
from .data import (
    txAssetFreeze,
    txAssetXfer,
    txAssetConfig,
    txKeyreg,
    txPayment,
    txApplication,
    txApplicationLong,
    txAprv
)


# In these tests we check the behavior of the device when asked to sign a transaction

# Account ID for the test
ACCOUNT_ID = 123

# Navigate instructions for Nano Devices
NANO_NAVIGATE_INSTRUCTIONS = NavInsID.RIGHT_CLICK
NANO_VALIDATE_INSTRUCTIONS = [NavInsID.BOTH_CLICK]

# Navigate instructions for Devices with touch screens
TOUCH_NAVIGATE_INSTRUCTIONS = NavInsID.SWIPE_CENTER_TO_LEFT
TOUCH_VALIDATE_INSTRUCTIONS = [NavInsID.USE_CASE_REVIEW_CONFIRM]
TOUCH_REJECT_INSTRUCTIONS = [
    NavInsID.USE_CASE_CHOICE_REJECT,
    NavInsID.USE_CASE_CHOICE_CONFIRM,
]


def sign_tx_and_verify(
    tx_to_sign,
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    """Sign a transaction on the device and verify the signature.

    This helper function performs the complete flow of:
    1. Retrieving the public key from the device
    2. Sending a transaction to the device for signing
    3. Navigating through the on-screen approval flow
    4. Verifying the returned signature is valid

    Args:
        tx_to_sign: The transaction to sign (as a list of integers or hex string)
        backend: The backend interface to communicate with the device
        navigator: The navigator to perform on-screen interactions
        test_name: Name of the test for screenshot comparison
        default_screenshot_path: Path where screenshots should be saved

    Raises:
        AssertionError: If the signature verification fails
    """
    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key(account_id=ACCOUNT_ID)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    # Create the transaction to sign
    # Handle both list of integers and hex string formats
    if isinstance(tx_to_sign, str):
        transaction_blob = bytes.fromhex(tx_to_sign)
    else:
        transaction_blob = bytes(tx_to_sign)

    # Set navigate and validate instructions based on the device
    if backend.device.is_nano:
        navigate_instructions = NANO_NAVIGATE_INSTRUCTIONS
        validate_instructions = NANO_VALIDATE_INSTRUCTIONS
        text_to_search = "APPROVE"
    else:
        navigate_instructions = TOUCH_NAVIGATE_INSTRUCTIONS
        validate_instructions = TOUCH_VALIDATE_INSTRUCTIONS
        text_to_search = "Sign"

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(account_id=ACCOUNT_ID, transaction=transaction_blob):
        # Validate the on-screen request by performing the navigation appropriate for this device
        navigator.navigate_until_text_and_compare(
            navigate_instructions,
            validate_instructions,
            text_to_search,
            default_screenshot_path,
            test_name,
        )

    # The device as yielded the result, parse it and ensure that the signature is correct
    signature = client.get_async_response().data
    assert check_tx_signature_validity(public_key, signature, transaction_blob)


# In this test we send to the device a Sign Asset Freeze transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_asset_freeze_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    sign_tx_and_verify(
        txAssetFreeze,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


# In this test we send to the device a Sign Asset Transfer transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_asset_transfer_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    sign_tx_and_verify(
        txAssetXfer,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


# In this test we send to the device a Sign Asset Config transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_asset_config_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    sign_tx_and_verify(
        txAssetConfig,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


# In this test we send to the device a Sign Key Registration transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_keyreg_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    sign_tx_and_verify(
        txKeyreg,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


# In this test we send to the device a Sign Payment transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_payment_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    sign_tx_and_verify(
        txPayment,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


# In this test we send to the device a Sign Application transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_application_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    sign_tx_and_verify(
        txApplication,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


# In this test we send to the device a Sign Asset Freeze and Sign Application transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_asset_freeze_and_application_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    sign_tx_and_verify(
        txAssetFreeze,
        backend,
        navigator,
        test_name + "part1",
        default_screenshot_path,
    )

    sign_tx_and_verify(
        txApplication,
        backend,
        navigator,
        test_name + "part2",
        default_screenshot_path,
    )


# In this test we send to the device a Sign a long Application transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_application_long_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    sign_tx_and_verify(
        txApplicationLong,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )


# In this test we send to the device a Sign a long Application transaction to sign and skip some of the validation steps
# This test is only for devices with buttons (Nano S, S+, X)
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_application_long_shortcut_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:

    # Skip the test if the device is not a Nano S, S+, X
    if not backend.device.is_nano:
        pytest.skip("This test is only for devices with buttons (Nano S, S+, X)")
        return

    # Instructions to enable expert mode and shortcut mode
    enable_shortcut_mode_instructions = [
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # enable expert mode
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # enable shortcut mode
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # enable shortcut mode
    ]
    # Navigate and compare the screenshots
    navigator.navigate_and_compare(
        default_screenshot_path,
        test_name,
        enable_shortcut_mode_instructions,
        screen_change_before_first_instruction=False,
    )

    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Get the public key of the device (for verifying the signature)
    rapdu = client.get_address_and_public_key(account_id=ACCOUNT_ID)
    _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    # Create the transaction to sign
    # Handle both list of integers and hex string formats
    if isinstance(txApplicationLong, str):
        transaction_blob = bytes.fromhex(txApplicationLong)
    else:
        transaction_blob = bytes(txApplicationLong)

    # Set navigate and validate instructions based on the device
    navigate_instructions = NANO_NAVIGATE_INSTRUCTIONS
    validate_instructions = NANO_VALIDATE_INSTRUCTIONS
    text_to_search = "APPROVE"

    skip_and_approve_instructions = [
        NavInsID.RIGHT_CLICK,
        NavInsID.BOTH_CLICK,  # click on skip fields
        NavInsID.BOTH_CLICK,  # click on approve
    ]

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    with client.sign_tx(account_id=ACCOUNT_ID, transaction=transaction_blob):

        navigator.navigate_and_compare(
            default_screenshot_path,
            test_name,
            skip_and_approve_instructions,
            screen_change_before_first_instruction=False,
            snap_start_idx=11,
        )

    # The device as yielded the result, parse it and ensure that the signature is correct
    signature = client.get_async_response().data
    assert check_tx_signature_validity(public_key, signature, transaction_blob)


# In this test we send to the device a Sign APRV transaction to sign and validate it on screen
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_aprv_tx(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    
    tx_blob = encode_aprv_transaction(txAprv)
    
    sign_tx_and_verify(
        tx_blob,
        backend,
        navigator,
        test_name,
        default_screenshot_path,
    )



# Transaction signature refused test
# The test will ask for a transaction signature that will be refused on screen
def test_sign_tx_refused(
    backend: BackendInterface,
    navigator: Navigator,
    test_name: str,
    default_screenshot_path: str,
) -> None:
    # Use the app interface instead of raw interface
    client = AlgorandCommandSender(backend)

    # Create the transaction to sign
    transaction = bytes(txAssetFreeze)

    # Set navigate and validate instructions based on the device
    if backend.device.is_nano:
        navigate_instructions = NANO_NAVIGATE_INSTRUCTIONS
        validate_instructions = NANO_VALIDATE_INSTRUCTIONS
        text_to_search = "REJECT"
    else:
        navigate_instructions = TOUCH_NAVIGATE_INSTRUCTIONS
        validate_instructions = TOUCH_REJECT_INSTRUCTIONS
        text_to_search = "Reject"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.sign_tx(account_id=ACCOUNT_ID, transaction=transaction):
            navigator.navigate_until_text_and_compare(
                navigate_instructions,
                validate_instructions,
                text_to_search,
                default_screenshot_path,
                test_name,
            )

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_COMMAND_NOT_ALLOWED_EF
    assert len(e.value.data) == 0
