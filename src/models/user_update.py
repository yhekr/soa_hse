from typing import Optional
from pydantic import BaseModel

class UserUpdate(BaseModel):
    name: Optional[str] = None
    surname: Optional[str] = None
    birthday: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None