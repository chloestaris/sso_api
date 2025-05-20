# swagger.py
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask import Flask, json, jsonify
from marshmallow import Schema, fields

# Create an APISpec
spec = APISpec(
    title="Flask Authentication API",
    version="1.0.0",
    openapi_version="3.0.2",
    plugins=[MarshmallowPlugin()],
)

# Define schemas for request/response objects
class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    email_verified = fields.Bool(dump_only=True)
    created_at = fields.DateTime(dump_only=True)

class LoginRequestSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)

class LoginResponseSchema(Schema):
    message = fields.Str()
    token = fields.Str()
    expires_in = fields.Int()
    email_verified = fields.Bool()

class RegisterRequestSchema(Schema):
    username = fields.Str(required=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True)

# Register schemas with spec
spec.components.schema("User", schema=UserSchema)
spec.components.schema("LoginRequest", schema=LoginRequestSchema)
spec.components.schema("LoginResponse", schema=LoginResponseSchema)
spec.components.schema("RegisterRequest", schema=RegisterRequestSchema)

# Add basic info
spec.tag({"name": "Authentication", "description": "Authentication operations"})
spec.tag({"name": "User", "description": "User operations"})

# Document routes
def register_endpoints():
    # Register endpoint
    spec.path(
        path="/register",
        operations={
            "post": {
                "tags": ["Authentication"],
                "summary": "Register a new user",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/RegisterRequest"}
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "User created successfully",
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"message": {"type": "string"}}}
                            }
                        },
                    },
                    "400": {"description": "Bad request, missing fields or user already exists"},
                },
            }
        },
    )

    # Login endpoint
    spec.path(
        path="/login",
        operations={
            "post": {
                "tags": ["Authentication"],
                "summary": "Login to get an access token",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/LoginRequest"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginResponse"}
                            }
                        },
                    },
                    "401": {"description": "Invalid credentials"},
                },
            }
        },
    )

    # User profile endpoint
    spec.path(
        path="/user",
        operations={
            "get": {
                "tags": ["User"],
                "summary": "Get current user profile",
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": "User profile",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/User"}
                            }
                        },
                    },
                    "401": {"description": "Unauthorized"},
                },
            }
        },
    )

    # Email verification endpoint
    spec.path(
        path="/verify-email/{token}",
        operations={
            "get": {
                "tags": ["Authentication"],
                "summary": "Verify email address",
                "parameters": [
                    {
                        "name": "token",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {"description": "Email verified successfully"},
                    "400": {"description": "Invalid or expired token"},
                    "404": {"description": "User not found"},
                },
            }
        },
    )

    # Add security scheme
    spec.components.security_scheme(
        "bearerAuth",
        {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        },
    )

# Generate OpenAPI specification
register_endpoints()