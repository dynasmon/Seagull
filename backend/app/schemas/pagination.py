"""Common pagination schemas.

We keep these generic so multiple endpoints (events, alerts, inventory, ...)
can share the same response shape.
"""

from __future__ import annotations

from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field
from pydantic.generics import GenericModel


T = TypeVar("T")


class CursorPage(GenericModel, Generic[T]):
    """A cursor-paginated response.

    - items: payload list (size <= page_size)
    - next_cursor: cursor token to fetch the next page (older items)
    - has_more: indicates if there are more pages
    """

    items: List[T] = Field(default_factory=list)
    next_cursor: Optional[str] = Field(default=None, description="Cursor to fetch the next page")
    has_more: bool = Field(default=False, description="Whether more items are available")
