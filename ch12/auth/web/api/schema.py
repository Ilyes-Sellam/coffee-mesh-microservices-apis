from pydantic import BaseModel, EmailStr, constr, validator
from typing import Optional


class UserRegister(BaseModel):
    firstname: constr(min_length=1)  # Required first name
    lastname: Optional[constr(max_length=50)] = None  # Optional last name
    email: EmailStr
    password: constr(min_length=6)

    @validator("firstname")
    def validate_firstname(cls, v):
        # You can add custom validation for the first name if needed
        return v.strip()

    @validator("lastname", pre=True, always=True)
    def validate_lastname(cls, v):
        # Strip leading and trailing whitespaces from last name if provided
        return v.strip() if v is not None else v

class UserLogin(BaseModel):
    email: str
    password: str
