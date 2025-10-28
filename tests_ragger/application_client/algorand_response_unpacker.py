from typing import Tuple
from struct import unpack

# # remainder, data_len, data
# def pop_sized_buf_from_buffer(buffer:bytes, size:int) -> Tuple[bytes, bytes]:
#     return buffer[size:], buffer[0:size]

# # remainder, data_len, data
# def pop_size_prefixed_buf_from_buf(buffer:bytes) -> Tuple[bytes, int, bytes]:
#     data_len = buffer[0]
#     return buffer[1+data_len:], data_len, buffer[1:data_len+1]

# # Unpack from response:
# # response = app_name (var)
# def unpack_get_app_name_response(response: bytes) -> str:
#     return response.decode("ascii")


# Unpack from response:
# response = test_mode (1)
#            MAJOR (2)
#            MINOR (2)
#            PATCH (2)
#            locked (1)
#            target_id (4)
def unpack_get_version_response(response: bytes) -> Tuple[int, int, int, int, int, int]:
    print(
        f"km-logs - [algorand_response_unpacker.py] (unpack_get_version_response) - length: {len(response)}"
    )
    assert len(response) == 12  # 000002000500070033000004
    # Format: >B = test (1 byte), HHH = major/minor/patch (3x 2-byte big-endian), B = locked (1 byte), I = target_id (4-byte big-endian)
    test_mode, major, minor, patch, locked, target_id = unpack(">BHHHBI", response)
    return (test_mode, major, minor, patch, locked, target_id)


# # Unpack from response:
# # response = format_id (1)
# #            app_name_raw_len (1)
# #            app_name_raw (var)
# #            version_raw_len (1)
# #            version_raw (var)
# #            unused_len (1)
# #            unused (var)
# def unpack_get_app_and_version_response(response: bytes) -> Tuple[str, str]:
#     response, _ = pop_sized_buf_from_buffer(response, 1)
#     response, _, app_name_raw = pop_size_prefixed_buf_from_buf(response)
#     response, _, version_raw = pop_size_prefixed_buf_from_buf(response)
#     response, _, _ = pop_size_prefixed_buf_from_buf(response)

#     assert len(response) == 0

#     return app_name_raw.decode("ascii"), version_raw.decode("ascii")


# Unpack from response:
# response = pub_key_len (1)
#            pub_key (var)
#            chain_code_len (1)
#            chain_code (var)
def unpack_get_public_key_response(response: bytes) -> Tuple[int, bytes, int, bytes]:
    print(
        f"km-logs - [algorand_response_unpacker.py] (unpack_get_public_key_response) - length: {len(response)}"
    )
    print(
        f"km-logs - [algorand_response_unpacker.py] (unpack_get_public_key_response) - response.hex(): {response.hex()}"
    )

    PUBKEY_LEN = 32
    ADDRESS_LEN = 58
    pubkey = response[:PUBKEY_LEN]

    address = response[PUBKEY_LEN : PUBKEY_LEN + ADDRESS_LEN]
    print(
        f"km-logs - [algorand_response_unpacker.py] (unpack_get_public_key_response) - left in response: {len(response[PUBKEY_LEN+ADDRESS_LEN:])}"
    )

    return PUBKEY_LEN, pubkey, ADDRESS_LEN, address

    # response, pub_key_len, pub_key = pop_size_prefixed_buf_from_buf(response)
    # response, chain_code_len, chain_code = pop_size_prefixed_buf_from_buf(response)

    # assert pub_key_len == 65
    # assert chain_code_len == 32
    # assert len(response) == 0

    # return pub_key_len, pub_key, chain_code_len, chain_code


# # Unpack from response:
# # response = der_sig_len (1)
# #            der_sig (var)
# #            v (1)
# def unpack_sign_tx_response(response: bytes) -> Tuple[int, bytes, int]:
#     response, der_sig_len, der_sig = pop_size_prefixed_buf_from_buf(response)
#     response, v = pop_sized_buf_from_buffer(response, 1)

#     assert len(response) == 0

#     return der_sig_len, der_sig, int.from_bytes(v, byteorder='big')
