from fastapi import FastAPI, HTTPException, Form
from ldap3 import Server, Connection, ALL

app = FastAPI()

LDAP_SERVER = "ldap://localhost"
LDAP_BASE_DN = "dc=us-east-2,dc=compute,dc=internal"

@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    user_dn = f"cn={username},{LDAP_BASE_DN}"
    server = Server(LDAP_SERVER, get_info=ALL)

    try:
        conn = Connection(server, user=user_dn, password=password, auto_bind=True)
        return {"message": "Login successful"}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"LDAP bind failed: {str(e)}")

