"""
This module helps to serialize and deserialize encrypted notes to and from JSON format.
"""

import json
from datetime import datetime
from enum import Enum
from typing import Any

from .models import NoteStatus


class EnumJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder for Enum and datetime.
    """

    def default(self, obj: Any) -> Any:
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


class EnumJSONDecoder(json.JSONDecoder):
    """
    Custom JSON decoder that handles enum conversion.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj: dict) -> dict:
        """
        Convert string values back to enums where appropriate.
        """

        if "status" in obj and isinstance(obj["status"], str):
            try:
                obj["status"] = NoteStatus(obj["status"])
            except ValueError:
                pass

        for key in ["created_at", "updated_at"]:
            if key in obj and isinstance(obj[key], str):
                try:
                    obj[key] = datetime.fromisoformat(obj[key])
                except ValueError:
                    pass

        return obj
