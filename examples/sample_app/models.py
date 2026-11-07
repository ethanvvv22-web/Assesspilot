from dataclasses import dataclass


@dataclass
class User:
    id: int
    email: str
    phone_number: str
    password_hash: str


@dataclass
class Payment:
    id: int
    user_id: int
    card_number: str = ""
    amount: float = 0.0
