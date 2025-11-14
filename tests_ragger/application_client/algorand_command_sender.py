from enum import IntEnum
from typing import Generator, Optional, List
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU  # type: ignore  # pylint: disable=import-error

from ..utils import pack_account_id

MAX_APDU_LEN: int = 250

CLA: int = 0x80


class AlgorandSigningError(Exception):
    """Exception raised when signing a transaction chunk fails."""


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for first account ID
    P1_FIRST_ACCOUNT_ID = 0x01
    # Parameter 1 for maximum APDU number.
    P1_MAX = 0x03
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01
    # Parameter 1 indicating account number present in first chunk
    P1_ACCOUNT_PRESENT = 0x01
    # Parameter 1 for more data coming
    P1_MORE = 0x80


class P2(IntEnum):
    # Parameter 2 for last APDU to receive.
    P2_LAST = 0x00
    # Parameter 2 for more APDU to receive.
    P2_MORE = 0x80


class InsType(IntEnum):
    GET_VERSION = 0x00
    GET_PUBLIC_KEY = 0x03
    GET_ADDRESS = 0x04
    SIGN_MSGPACK = 0x08
    SIGN_ARBITRARY_DATA = 0x10


class Errors(IntEnum):
    # Predefined error codes
    SW_SUCCESS = 0x9000
    SW_CONDITIONS_NOT_SATISFIED = 0x6985
    SW_COMMAND_NOT_ALLOWED_EF = 0x6986
    SW_INCORRECT_P1_P2 = 0x6A86
    SW_WRONG_DATA_LENGTH = 0x6A87
    SW_INVALID_INS = 0x6D00
    SW_INVALID_CLA = 0x6E00
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL = 0xB002
    SW_DISPLAY_AMOUNT_FAIL = 0xB003
    SW_WRONG_TX_LENGTH = 0xB004
    SW_TX_PARSING_FAIL = 0xB005
    SW_TX_HASH_FAIL = 0xB006
    SW_BAD_STATE = 0xB007
    SW_SIGNATURE_FAIL = 0xB008
    SW_WRONG_AMOUNT = 0xC000
    SW_WRONG_ADDRESS = 0xC000
    # Arbitrary sign error codes
    SW_INVALID_SCOPE = 0x6988
    SW_FAILED_DECODING = 0x6989
    SW_INVALID_SIGNER = 0x698A
    SW_MISSING_DOMAIN = 0x698B
    SW_MISSING_AUTH_DATA = 0x698C
    SW_BAD_JSON = 0x698D
    SW_FAILED_DOMAIN_AUTH = 0x698E
    SW_FAILED_HD_PATH = 0x698F


def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


def add_account_id_to_message(message: bytes, account_id: int) -> bytes:
    if account_id != 0:
        return pack_account_id(account_id) + message

    return message


class AlgorandCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend

    # def get_app_and_version(self) -> RAPDU:
    #     return self.backend.exchange(
    #         cla=0xB0,  # specific CLA for BOLOS
    #         ins=0x01,  # specific INS for get_app_and_version
    #         p1=P1.P1_START,
    #         p2=P2.P2_LAST,
    #         data=b"",
    #     )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_START, p2=P2.P2_LAST, data=b""
        )

    # def get_app_name(self) -> RAPDU:
    #     return self.backend.exchange(
    #         cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_START, p2=P2.P2_LAST, data=b""
    #     )

    @contextmanager
    def get_address_and_public_key_with_confirmation(
        self, account_id: int
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_ADDRESS,
            p1=P1.P1_CONFIRM,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        ) as response:
            yield response

    def get_address_and_public_key(self, account_id: int) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_ADDRESS,
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        )

    # Deprecated use get_address_and_public_key instead
    @contextmanager
    def get_public_key_with_confirmation(
        self, account_id: int
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_CONFIRM,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        ) as response:
            yield response

    # Deprecated use get_address_and_public_key instead
    def get_public_key(self, account_id: int) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_LAST,
            data=pack_account_id(account_id),
        )

    @contextmanager
    def sign_tx(
        self, account_id: int, transaction: bytes
    ) -> Generator[None, None, None]:
        # Add the account id to the transaction
        message = add_account_id_to_message(transaction, account_id)
        # Split the transaction into chunks
        chunks = split_message(message, MAX_APDU_LEN)
        # Get the number of chunks
        num_of_chunks = len(chunks)
        # Sπaet the p1 value
        p1 = P1.P1_FIRST_ACCOUNT_ID if account_id != 0 else P1.P1_START

        # Send all chunks except the last one
        if num_of_chunks > 1:
            for i in range(0, num_of_chunks - 1):
                rapdu = self.backend.exchange(
                    cla=CLA,
                    ins=InsType.SIGN_MSGPACK,
                    p1=p1 if i == 0 else P1.P1_MORE,
                    p2=P2.P2_MORE,
                    data=chunks[i],
                )

                if rapdu.status != Errors.SW_SUCCESS:
                    raise AlgorandSigningError(f"Error after sending chunk number {i}: {rapdu.status}")

        # Send the last chunk
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.SIGN_MSGPACK,
            p1=P1.P1_MORE if len(chunks) > 1 else P1.P1_FIRST_ACCOUNT_ID,
            p2=P2.P2_LAST,
            data=chunks[-1],
        ) as response:
            yield response

    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response

    # def sign_tx_sync(self, path: str, transaction: bytes) -> Optional[RAPDU]:
    #     with self.sign_tx(path, transaction):
    #         pass
    #     rapdu = self.get_async_response()
    #     assert isinstance(rapdu, RAPDU)
    #     return rapdu
