#!/bin/bash

# Configuration
BASE_URL="${SSO_API_URL:-http://localhost:5000}"
REDIRECT_URI="${CLIENT_REDIRECT_URI:-http://localhost:8000/callback}"
USERNAME="testuser"
PASSWORD="testpassword123"
EMAIL="test@example.com"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to extract values from JSON
extract_json_value() {
    if echo "$1" | jq -e . >/dev/null 2>&1; then
        echo "$1" | jq -r ".$2"
    else
        echo -e "${RED}Invalid JSON response:${NC}\n$1"
        return 1
    fi
}

# Function to debug curl response
debug_response() {
    local response="$1"
    local step="$2"
    local http_code="$3"
    local location="$4"
    echo -e "${YELLOW}Debug output for $step:${NC}"
    echo -e "${YELLOW}Raw response:${NC}"
    echo "$response"
    echo -e "${YELLOW}Response length:${NC} ${#response}"
    echo -e "${YELLOW}HTTP response code:${NC} $http_code"
    if [ ! -z "$location" ]; then
        echo -e "${YELLOW}Location header:${NC} $location"
    fi
}

# Function to generate PKCE values using Python
generate_pkce() {
    python3 -c '
import base64
import hashlib
import secrets

code_verifier = secrets.token_urlsafe(32)
code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")
print(f"{code_verifier}\n{code_challenge}")
'
}

echo -e "${GREEN}Generating PKCE values...${NC}"
PKCE_VALUES=$(generate_pkce)
CODE_VERIFIER=$(echo "$PKCE_VALUES" | head -n 1)
CODE_CHALLENGE=$(echo "$PKCE_VALUES" | tail -n 1)

echo "Code Verifier: $CODE_VERIFIER"
echo "Code Challenge: $CODE_CHALLENGE"

# Wait for API to be ready
echo -e "\n${GREEN}Waiting for SSO API to be ready...${NC}"
until curl -s "$BASE_URL/health" > /dev/null; do
    echo "Waiting for API..."
    sleep 2
done

# Step 0: Register user
echo -e "\n${GREEN}0. Registering test user...${NC}"
REGISTER_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$USERNAME\",
    \"password\": \"$PASSWORD\",
    \"email\": \"$EMAIL\"
  }")
HTTP_CODE=$(echo "$REGISTER_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
REGISTER_RESPONSE=$(echo "$REGISTER_RESPONSE" | sed '/HTTP_CODE:/d')

debug_response "$REGISTER_RESPONSE" "Registration" "$HTTP_CODE"

# Step 0.5: Get verification token and verify email
echo -e "\n${GREEN}0.5. Getting verification token...${NC}"
# Trigger email generation
curl -s -X GET "$BASE_URL/test-verification/$USERNAME" > /dev/null

# Extract verification URL from Docker logs
VERIFY_RESPONSE=$(docker logs sso_api-sso_api-1 2>&1 | grep -o 'http://localhost:5000/verify-email/[^ ]*' | tail -n 1)

if [ -z "$VERIFY_RESPONSE" ]; then
    echo -e "${RED}Failed to extract verification URL from logs${NC}"
    exit 1
fi

echo -e "\n${GREEN}0.6. Verifying email with token...${NC}"
VERIFY_TOKEN_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "$VERIFY_RESPONSE")
HTTP_CODE=$(echo "$VERIFY_TOKEN_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
VERIFY_TOKEN_RESPONSE=$(echo "$VERIFY_TOKEN_RESPONSE" | sed '/HTTP_CODE:/d')

debug_response "$VERIFY_TOKEN_RESPONSE" "Email Verification" "$HTTP_CODE"

# Step 1: Login to get JWT token
echo -e "\n${GREEN}1. Logging in as user...${NC}"
LOGIN_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$USERNAME\",
    \"password\": \"$PASSWORD\"
  }")
HTTP_CODE=$(echo "$LOGIN_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
LOGIN_RESPONSE=$(echo "$LOGIN_RESPONSE" | sed '/HTTP_CODE:/d')

debug_response "$LOGIN_RESPONSE" "Login" "$HTTP_CODE"

# Extract JWT token
JWT_TOKEN=$(extract_json_value "$LOGIN_RESPONSE" "token")
if [ -z "$JWT_TOKEN" ]; then
    echo -e "${RED}Failed to get JWT token${NC}"
    exit 1
fi

# Step 2: Create OAuth client
echo -e "\n${GREEN}2. Creating OAuth client...${NC}"
CLIENT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/oauth/init-admin-client" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"Test Client\",
    \"redirect_uri\": \"$REDIRECT_URI\"
  }")
HTTP_CODE=$(echo "$CLIENT_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
CLIENT_RESPONSE=$(echo "$CLIENT_RESPONSE" | sed '/HTTP_CODE:/d')

debug_response "$CLIENT_RESPONSE" "Client Creation" "$HTTP_CODE"

# Extract client credentials
CLIENT_ID=$(extract_json_value "$CLIENT_RESPONSE" "client_id")
CLIENT_SECRET=$(extract_json_value "$CLIENT_RESPONSE" "client_secret")
if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
    echo -e "${RED}Failed to get client credentials${NC}"
    exit 1
fi

# Step 3: Get authorization code
echo -e "\n${GREEN}3. Getting authorization code...${NC}"
# Submit the authorization form directly (skipping the form display)
AUTH_RESPONSE=$(curl -s -D - -X POST \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "confirm=Authorize" \
  "$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=profile&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256")

# Extract the Location header from the response headers
LOCATION=$(echo "$AUTH_RESPONSE" | grep -i "^location:" | cut -d' ' -f2- | tr -d '\r')
debug_response "$AUTH_RESPONSE" "Authorization" "302" "$LOCATION"

# Extract code from the Location header
AUTH_CODE=$(echo "$LOCATION" | grep -o 'code=[^&]*' | cut -d'=' -f2)
if [ -z "$AUTH_CODE" ]; then
    echo -e "${RED}Failed to get authorization code${NC}"
    echo -e "${YELLOW}Location header:${NC} $LOCATION"
    exit 1
fi
echo "Authorization code: $AUTH_CODE"

# Step 4: Exchange code for OAuth2 token
echo -e "\n${GREEN}4. Exchanging code for OAuth2 token...${NC}"
TOKEN_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$BASE_URL/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER")
HTTP_CODE=$(echo "$TOKEN_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
TOKEN_RESPONSE=$(echo "$TOKEN_RESPONSE" | sed '/HTTP_CODE:/d')

debug_response "$TOKEN_RESPONSE" "Token Exchange" "$HTTP_CODE"

# Extract OAuth2 token
OAUTH2_TOKEN=$(extract_json_value "$TOKEN_RESPONSE" "access_token")
if [ -z "$OAUTH2_TOKEN" ]; then
    echo -e "${RED}Failed to get OAuth2 token${NC}"
    echo -e "${YELLOW}Client ID:${NC} $CLIENT_ID"
    echo -e "${YELLOW}Auth Code:${NC} $AUTH_CODE"
    echo -e "${YELLOW}Code Verifier:${NC} $CODE_VERIFIER"
    exit 1
fi

# Step 5: Test the OAuth2 token
echo -e "\n${GREEN}5. Testing OAuth2 token with userinfo endpoint...${NC}"
USERINFO_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$BASE_URL/oauth/userinfo" \
  -H "Authorization: Bearer $OAUTH2_TOKEN" \
  -v)  # Added -v for verbose output
HTTP_CODE=$(echo "$USERINFO_RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
USERINFO_RESPONSE=$(echo "$USERINFO_RESPONSE" | sed '/HTTP_CODE:/d')

debug_response "$USERINFO_RESPONSE" "Userinfo" "$HTTP_CODE"

if echo "$USERINFO_RESPONSE" | jq -e . >/dev/null 2>&1; then
    echo -e "\n${GREEN}Test completed successfully!${NC}"
    echo "JWT Token: $JWT_TOKEN"
    echo "OAuth2 Token: $OAUTH2_TOKEN"
else
    echo -e "\n${RED}Failed to get user info${NC}"
    exit 1
fi