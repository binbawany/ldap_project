from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from ..auth import create_access_token, verify_token
from ..monitor import get_system_metrics
from ldap3 import Server, Connection, ALL

router = APIRouter(prefix="/api/v1")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/login")

LDAP_SERVER = "ldap://localhost"
LDAP_BASE_DN = "dc=us-east-2,dc=compute,dc=internal"

@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    user_dn = f"cn={username},{LDAP_BASE_DN}"

    server = Server(LDAP_SERVER, get_info=ALL)
    try:
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid LDAP credentials")

    role = "admin" if username == "admin" else "user"
    token = create_access_token({"sub": username, "role": role})
    return {"access_token": token, "token_type": "bearer"}

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return payload

@router.get("/profile")
def profile(user: dict = Depends(get_current_user)):
    return {"username": user["sub"], "role": user["role"]}

@router.get("/monitor")
def monitor(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admins only")
    return get_system_metrics()

