import hashlib
import uuid


class AuthSystem:

    def __init__(self):
        # Unique internal framework security salt to harden hash algorithms against rainbow tables
        self._security_salt = "AI_SOC_PLATFORM_GUARD_SALT_2026_#"

        # Static Demo Users: In-memory dictionaries configured securely
        self.users = {
            "admin": {
                "password": self.hash_password("admin123"),
                "role": "ADMIN"
            },
            "analyst": {
                "password": self.hash_password("analyst123"),
                "role": "ANALYST"
            }
        }

        # Session persistence cache tracking active session cookies
        self.sessions = {}

    # =========================
    # HASH PASSWORD WITH SALT
    # =========================
    def hash_password(self, password):
        """Generates salted SHA256 digests with safe input types protections."""
        if not password:
            password = ""
            
        # Salted hashing technique integration block
        salted_payload = f"{password}{self._security_salt}"
        return hashlib.sha256(salted_payload.encode('utf-8')).hexdigest()

    # =========================
    # LIVE ANALYST AUTH PANEL
    # =========================
    def login(self, username, password):
        """Validates incoming operator identifiers against system dictionary records."""
        # Standard input sanitation boundaries mapping
        if not username:
            username = ""
        if not password:
            password = ""

        # Remove extra white spacing if any
        username = str(username).strip()

        # Input data validation bounds check
        if not username or not password:
            return {
                "status": "fail", 
                "message": "Username and password details cannot be evaluated as empty strings."
            }

        # Target lookup existence check
        if username not in self.users:
            return {"status": "fail", "message": "User identifier records not found inside database."}

        # Computed dynamic password verification block
        hashed_attempt = self.hash_password(password)
        if self.users[username]["password"] != hashed_attempt:
            return {"status": "fail", "message": "Invalid password credentials validation exception."}

        # Secure UUID authorization token string allocation
        session_token = str(uuid.uuid4())

        # Bind token properties schema mappings definitions
        self.sessions[session_token] = {
            "username": username,
            "role": self.users[username]["role"]
        }

        print(f"[AUTH SYSTEM] Operator '{username}' successfully verified. Token generated.")
        return {
            "status": "success",
            "token": session_token,
            "role": self.users[username]["role"]
        }

    # =========================
    # VERIFY ACTIVE SESSION TOKEN
    # =========================
    def verify(self, token):
        """Extracts active operator properties schema maps directly via session token IDs."""
        if not token:
            return None
        return self.sessions.get(str(token).strip(), None)

    # =========================
    # SECURITY ROLE CHECKS BOUNDS
    # =========================
    def require_role(self, token, role):
        """Enforces access privilege boundaries checks over specific visual display panes."""
        if not token or not role:
            return False

        session = self.verify(token)
        if not session:
            return False

        # Structural case matches comparison checks
        return str(session.get("role", "")).upper() == str(role).upper()


# =========================
# STANDALONE COMPONENT DRY-RUN TEST
# =========================
if __name__ == "__main__":
    print("--- Initializing Auth Validation Systems Suite ---")
    auth = AuthSystem()

    print("\n--- Execution Step 1: Validating Correct Admin Matrix Login ---")
    success_test = auth.login("admin", "admin123")
    print(success_test)

    print("\n--- Execution Step 2: Validating Boundary Error Crash Resilience ---")
    boundary_test = auth.login(None, None)
    print(boundary_test)

    print("\n--- Execution Step 3: Verifying Role Mapping Validations Layouts ---")
    if success_test.get("status") == "success":
        active_token = success_test.get("token")
        is_allowed = auth.require_role(active_token, "ADMIN")
        print(f"Is Assigned Token verified for target ADMIN permissions? -> {is_allowed}")