import pytest

from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator.navigation_scenario import NavigateWithScenario
from ragger.navigator import NavInsID, Navigator

# from .application_client.algorand_transaction import Transaction
from .application_client.algorand_command_sender import AlgorandCommandSender, Errors
from .application_client.algorand_response_unpacker import (
    unpack_get_public_key_response,
)
from .utils import check_signature_validity
from .data import txAssetFreeze


# In this tests we check the behavior of the device when asked to sign a transaction

# Account ID for the test
ACCOUNT_ID = 123

# Navigate instructions for Nano Devices
NANO_NAVIGATE_INSTRUCTIONS = NavInsID.RIGHT_CLICK
NANO_VALIDATE_INSTRUCTIONS = [NavInsID.BOTH_CLICK]

# Navigate instructions for Devices with touch screens
TOUCH_NAVIGATE_INSTRUCTIONS = NavInsID.SWIPE_CENTER_TO_LEFT
TOUCH_VALIDATE_INSTRUCTIONS = [NavInsID.USE_CASE_REVIEW_CONFIRM]


def sign_tx_and_verify(
    tx_to_sign: str,
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
        tx_to_sign: The transaction bytes to sign (as a list of integers)
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
    assert check_signature_validity(public_key, signature, transaction_blob)


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


# # In this test we send to the device a transaction to trig a blind-signing flow
# # The transaction is short and will be sent in one chunk
# # We will ensure that the displayed information is correct by using screenshots comparison
# def test_sign_tx_short_tx_blind_sign(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
#     # Use the app interface instead of raw interface
#     client = AlgorandCommandSender(backend)
#     # The path used for this entire test
#     path: str = "m/44'/1'/0'/0/0"

#     # First we need to get the public key of the device in order to build the transaction
#     rapdu = client.get_public_key(path=path)
#     _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

#     # Create the transaction that will be sent to the device for signing
#     transaction = Transaction(
#         nonce=1,
#         to="0x0000000000000000000000000000000000000000",
#         value=0,
#         memo="Blind-sign"
#     ).serialize()

#     # As it requires on-screen validation, the function is asynchronous.
#     # It will yield the result when the navigation is done
#     with client.sign_tx(path=path, transaction=transaction):
#         # Validate the on-screen request by performing the navigation appropriate for this device
#         scenario_navigator.review_approve_with_warning(warning_path="part1")

#     # The device as yielded the result, parse it and ensure that the signature is correct
#     response = client.get_async_response().data
#     _, der_sig, _ = unpack_sign_tx_response(response)
#     assert check_signature_validity(public_key, der_sig, transaction)

# # In this test se send to the device a transaction to sign and validate it on screen
# # This test is mostly the same as the previous one but with different values.
# # In particular the long memo will force the transaction to be sent in multiple chunks
# def test_sign_tx_long_tx(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
#     # Use the app interface instead of raw interface
#     client = AlgorandCommandSender(backend)
#     path: str = "m/44'/1'/0'/0/0"

#     rapdu = client.get_public_key(path=path)
#     _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

#     transaction = Transaction(
#         nonce=1,
#         to="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
#         value=666,
#         memo=("This is a very long memo. "
#               "It will force the app client to send the serialized transaction to be sent in chunk. "
#               "As the maximum chunk size is 255 bytes we will make this memo greater than 255 characters. "
#               "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, "
#               "dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam.")
#     ).serialize()

#     with client.sign_tx(path=path, transaction=transaction):
#         scenario_navigator.review_approve()

#     response = client.get_async_response().data
#     _, der_sig, _ = unpack_sign_tx_response(response)
#     assert check_signature_validity(public_key, der_sig, transaction)


# # Transaction signature refused test
# # The test will ask for a transaction signature that will be refused on screen
# def test_sign_tx_refused(backend: BackendInterface, scenario_navigator: NavigateWithScenario) -> None:
#     # Use the app interface instead of raw interface
#     client = AlgorandCommandSender(backend)
#     path: str = "m/44'/1'/0'/0/0"

#     transaction = Transaction(
#         nonce=1,
#         to="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
#         value=666,
#         memo="This transaction will be refused by the user"
#     ).serialize()

#     with pytest.raises(ExceptionRAPDU) as e:
#         with client.sign_tx(path=path, transaction=transaction):
#             scenario_navigator.review_reject()

#     # Assert that we have received a refusal
#     assert e.value.status == Errors.SW_DENY
#     assert len(e.value.data) == 0
