# Authentication Documentation

## Overview

This FastAPI application uses **OAuth2 with JWT (JSON Web Tokens)** for authentication, following FastAPI security best practices.

## Authentication Flow

### 1. Login and Get Token

To authenticate, send a POST request to `/auth/token` with form data:

```bash
curl -X POST "http://localhost:8000/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=mrodriguez&password=art123"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### 2. Access Protected Endpoints

Use the token in the Authorization header with "Bearer" prefix:

```bash
curl -X GET "http://localhost:8000/auth/me" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

Response:
```json
{
  "username": "mrodriguez",
  "display_name": "Ms. Rodriguez",
  "role": "teacher"
}
```

### 3. Protected Endpoints

The following endpoints require authentication:

- `POST /activities/{activity_name}/signup` - Sign up a student for an activity
- `POST /activities/{activity_name}/unregister` - Remove a student from an activity
- `GET /auth/me` - Get current user information

Example of signing up a student:

```bash
curl -X POST "http://localhost:8000/activities/Chess%20Club/signup?email=student@example.com" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Technical Details

### JWT Token Configuration

- **Algorithm**: HS256
- **Expiration**: 30 minutes
- **Token Location**: Authorization header with Bearer scheme

### Password Security

- **Hashing Algorithm**: Argon2 (via argon2-cffi)
- Passwords are hashed before storage
- Password verification uses constant-time comparison

### Dependencies

Required packages:
- `pyjwt==2.8.0` - JWT token generation and validation
- `python-multipart==0.0.9` - Form data parsing for OAuth2
- `argon2-cffi==23.1.0` - Password hashing

## Default Test Accounts

The following teacher accounts are available for testing:

| Username | Password | Display Name | Role |
|----------|----------|--------------|------|
| mrodriguez | art123 | Ms. Rodriguez | teacher |
| mchen | chess456 | Mr. Chen | teacher |
| principal | admin789 | Principal Martinez | admin |

## Security Notes

⚠️ **Important for Production:**

1. **Change the SECRET_KEY**: The current SECRET_KEY in `src/backend/routers/auth.py` is a placeholder. In production, use a strong, randomly generated secret stored in an environment variable.

2. **Use HTTPS**: Always use HTTPS in production to protect tokens in transit.

3. **Token Storage**: Store tokens securely on the client side (e.g., httpOnly cookies or secure storage).

4. **Token Expiration**: Tokens expire after 30 minutes. Implement token refresh logic for better user experience.

## Implementation Details

### OAuth2 Password Bearer

The application uses `OAuth2PasswordBearer` from FastAPI's security utilities:

```python
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
```

### Dependency Injection

Protected endpoints use the `get_current_user` dependency:

```python
@router.post("/{activity_name}/signup")
def signup_for_activity(
    activity_name: str, 
    email: str,
    current_user: Annotated[User, Depends(get_current_user)]
):
    # Endpoint logic...
```

This automatically validates the JWT token and extracts user information.

## API Documentation

FastAPI automatically generates interactive API documentation at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

These interfaces include a built-in "Authorize" button to test authentication flows.
