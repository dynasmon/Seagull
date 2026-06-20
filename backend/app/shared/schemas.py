
from __future__ import annotations

from typing import Generic, List, Optional, TypeVar

from pydantic import Field
from pydantic.generics import GenericModel

T = TypeVar("T")


class CursorPage(GenericModel, Generic[T]):

    items: List[T] = Field(default_factory=list)
    next_cursor: Optional[str] = Field(default=None, description="Cursor to fetch the next page")
    has_more: bool = Field(default=False, description="Whether more items are available")
