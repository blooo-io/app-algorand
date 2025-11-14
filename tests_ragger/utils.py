from pathlib import Path

from typing import List
import re

import ed25519  # type: ignore[import-not-found]


# Check if a signature of a given message is valid
def check_signature_validity(
    public_key: bytes, signature: bytes, message: bytes
) -> bool:
    """Verify Ed25519 signature for Algorand transaction.

    Algorand transactions are signed with a "TX" prefix as per the Algorand protocol.
    The signature is Ed25519 in raw 64-byte format (not DER encoded).

    Args:
        public_key: 32-byte Ed25519 public key
        signature: 64-byte Ed25519 signature
        message: Transaction bytes (will be prefixed with "TX")

    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Create verifying key from public key bytes
        verifying_key = ed25519.VerifyingKey(public_key)

        # Algorand protocol: prepend "TX" to the transaction bytes before signing
        prefixed_message = b"TX" + message

        # Verify the signature (raises BadSignatureError if invalid)
        verifying_key.verify(signature, prefixed_message)
        return True
    except ed25519.BadSignatureError:
        # Signature verification failed
        return False
    except Exception:
        # Other errors (e.g., invalid key format)
        return False


# def verify_name(name: str) -> None:
#     """Verify the app name, based on defines in Makefile

#     Args:
#         name (str): Name to be checked
#     """

#     name_str = ""
#     lines = _read_makefile()
#     name_re = re.compile(r"^APPNAME\s?=\s?\"?(?P<val>\w+)\"?", re.I)
#     for line in lines:
#         info = name_re.match(line)
#         if info:
#             dinfo = info.groupdict()
#             name_str = dinfo["val"]
#     assert name == name_str


def verify_version(version: str) -> None:
    """Verify the app version, based on defines in app/Makefile

    Args:
        Version (str): Version to be checked
    """

    vers_dict = {}
    vers_str = ""
    lines = _read_makefile()
    version_re = re.compile(r"^APPVERSION_(?P<part>\w)\s?=\s?(?P<val>\d*)", re.I)
    for line in lines:
        info = version_re.match(line)
        if info:
            dinfo = info.groupdict()
            vers_dict[dinfo["part"]] = dinfo["val"]
    try:
        vers_str = f"{vers_dict['M']}.{vers_dict['N']}.{vers_dict['P']}"
    except KeyError:
        pass
    assert version == vers_str


def _read_makefile() -> List[str]:
    """Read lines from the app/Makefile.version"""

    parent = Path(__file__).parent.parent.resolve()
    makefile = f"{parent}/app/Makefile.version"
    with open(makefile, "r", encoding="utf-8") as f_p:
        lines = f_p.readlines()
    return lines


def pack_account_id(account_id: int) -> bytes:
    """Pack an account ID as a 32-bit big-endian unsigned integer.

    Args:
        account_id (int): The account ID to pack

    Returns:
        bytes: 4-byte big-endian representation of the account ID
    """
    return account_id.to_bytes(4, byteorder="big")
