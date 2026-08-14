from __future__ import annotations

from sqlalchemy import BigInteger, Integer
from sqlalchemy.types import TypeEngine

BigIntId: TypeEngine = BigInteger().with_variant(Integer(), "sqlite")
