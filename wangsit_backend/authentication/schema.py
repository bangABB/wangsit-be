from typing import Optional
from ninja import Schema
from pydantic import Field

class TokenSchema(Schema):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    email: str
    name: Optional[str] = None
    asal_sekolah: Optional[str] = None

class GoogleAuthSchema(Schema):
    code: str = Field(..., description="Authorization code from Google")
    redirect_uri: str = Field(..., description="Client redirect URI")
    asal_sekolah: Optional[str] = None

class UserProfileSchema(Schema):
    user_id: int
    email: str
    name: Optional[str] = None
    asal_sekolah: Optional[str] = None
    
class ProfileUpdateSchema(Schema):
    name: Optional[str] = Field(None, description="Name of the user")
    asal_sekolah: Optional[str] = Field(None, description="Asal sekolah (school origin) of the user")
