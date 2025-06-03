# Flask Authentication API with OAuth2/SSO

A robust Flask-based authentication system that provides both traditional JWT-based authentication and OAuth2/SSO capabilities. The system includes email verification, token management, and comprehensive OAuth2 client management.

## Features

- **User Authentication**
  - Traditional username/password authentication
  - JWT token-based authentication
  - Email verification system
  - Password hashing using PBKDF2-SHA256

- **OAuth2/SSO Support**
  - Authorization Code flow with PKCE
  - Token endpoint with refresh token support
  - UserInfo endpoint (OpenID Connect compatible)
  - OAuth2 client management
  - RSA key-based token signing
  - Scope-based access control

- **Security Features**
  - PKCE (Proof Key for Code Exchange) requirement
  - RSA key pair rotation support
  - Token expiration and revocation
  - Email verification requirement for sensitive operations
  - Secure password hashing

- **API Documentation**
  - Swagger/OpenAPI documentation
  - Interactive API documentation UI

## Prerequisites

- Python 3.7+
- SQLite3
- Docker (optional)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd sso_api
```

2. Create and activate a virtual environment:
```