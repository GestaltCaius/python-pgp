from typing import Any, TypedDict

OP_CODE_KEY = b'KEY'
OP_CODE_MSG = b'MSG'


class SecretMessage(TypedDict):
    op_code: bytes  # b'MSG' or b'KEY' to either send a message or exchange key
    data: Any  # Encrypted message or key
    user_id: int  # User's ID
