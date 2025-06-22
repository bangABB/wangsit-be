import json
import requests
from django.conf import settings
from django.contrib.auth.models import User
from django.http import HttpResponseRedirect, JsonResponse
from ninja import NinjaAPI, Router
from ninja.security import HttpBearer
import jwt
from datetime import datetime, timedelta
import urllib.parse
from typing import Dict, Any

from .schema import TokenSchema, GoogleAuthSchema, UserProfileSchema, ProfileUpdateSchema
from .models import UserProfile, ActivityLog

api = NinjaAPI(
    title="Wangsit API", 
    version="1.0.0",
    urls_namespace="wangsit_api",
    csrf=False,  # Disable CSRF for API to allow cross-origin requests
)
router = Router()
api.add_router("/auth/", router)

# JWT Bearer authentication
class JWTAuth(HttpBearer):
    def authenticate(self, request, token):
        try:
            # Decode the token and verify signature
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            
            # Check if token is expired
            exp = payload.get('exp')
            if exp and datetime.fromtimestamp(exp) < datetime.utcnow():
                return None
            
            # Return the payload which will be accessible in the endpoint
            return payload
        except jwt.PyJWTError:
            # Invalid token
            return None

@router.post("/google", response=TokenSchema)
def google_auth(request, auth_data: GoogleAuthSchema):
    """
    Exchange Google OAuth authorization code for user information and JWT token
    """
    try:
        # Exchange authorization code for access token
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            'code': auth_data.code,
            'client_id': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY,
            'client_secret': settings.SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET,
            'redirect_uri': auth_data.redirect_uri,
            'grant_type': 'authorization_code'
        }
        
        # Debug info
        print(f"Exchanging Google code for token with data: {data}")
        
        response = requests.post(token_url, data=data)
        token_data = response.json()
        
        if 'error' in token_data:
            print(f"Error from Google: {token_data}")
            return JsonResponse({
                'detail': token_data.get('error_description', token_data.get('error', 'Unknown error')),
                'google_error': token_data
            }, status=400)
        
        # Get user info from Google
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        headers = {'Authorization': f"Bearer {token_data['access_token']}"}
        
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()
        
        if 'error' in user_info:
            print(f"Error getting user info: {user_info}")
            return JsonResponse({
                'detail': 'Failed to get user information from Google',
                'google_error': user_info
            }, status=400)
        
        # Get or create user
        try:
            user = User.objects.get(email=user_info['email'])
        except User.DoesNotExist:
            username = user_info['email']
            # Ensure username is unique
            if User.objects.filter(username=username).exists():
                username = f"{username}_{user_info.get('sub', '')[:8]}"
                
            user = User.objects.create_user(
                username=username,
                email=user_info['email'],
                first_name=user_info.get('given_name', ''),
                last_name=user_info.get('family_name', '')
            )
            
            # Add asal_sekolah if provided
            if auth_data.asal_sekolah:
                user.profile.asal_sekolah = auth_data.asal_sekolah
                user.profile.save()
        
        # Generate JWT token with profile info
        payload = {
            'user_id': user.id,
            'email': user.email,
            'name': f"{user.first_name} {user.last_name}".strip(),
            'asal_sekolah': user.profile.asal_sekolah,
            'exp': datetime.utcnow() + timedelta(days=1)
        }
        
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
        
        return {
            'access_token': token,
            'token_type': 'bearer',
            'user_id': user.id,
            'email': user.email,
            'name': payload['name'],
            'asal_sekolah': user.profile.asal_sekolah,
        }
        
    except Exception as e:
        print(f"Exception in google_auth: {str(e)}")
        return JsonResponse({
            'detail': f'Authentication failed: {str(e)}',
        }, status=500)

@router.get("/google/login/")
def google_login(request):
    """Redirect to Google OAuth2 authorization URL"""
    # Use a properly registered redirect URI - must match what's in Google Cloud Console
    redirect_uri = request.GET.get('redirect_uri')
    
    if not redirect_uri:
        # Default fallback - this must be registered in Google Cloud Console
        redirect_uri = "http://localhost:3000/auth/callback"
    
    scope = 'email profile'
    
    # URL encode the redirect URI
    encoded_redirect_uri = urllib.parse.quote(redirect_uri)
    
    auth_url = (
        f"https://accounts.google.com/o/oauth2/auth"
        f"?client_id={settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY}"
        f"&redirect_uri={encoded_redirect_uri}"
        f"&scope={scope}"
        f"&response_type=code"
        f"&access_type=offline"
    )
    
    return HttpResponseRedirect(auth_url)

@router.get("/callback/")
def oauth_callback(request):
    """Handle the OAuth callback from Google"""
    code = request.GET.get('code')
    error = request.GET.get('error')
    
    if error:
        return JsonResponse({"error": error})
    
    if not code:
        return JsonResponse({"error": "No authorization code received"})
    
    # Create a simple HTML page that will extract the code and send it to your frontend
    html_response = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authentication Successful</title>
        <script>
            // The code from Google OAuth
            const code = "{code}";
            
            // Send this code to your frontend application
            window.onload = function() {{
                // You can modify this to send to your actual frontend URL
                // For example, if your frontend is at https://myapp.com
                window.location.href = "http://localhost:3000/auth?code=" + code;
                
                // If you want to use postMessage instead:
                // window.opener.postMessage({{ code: code }}, "http://localhost:3000");
                // window.close();
            }};
        </script>
    </head>
    <body>
        <h2>Authentication Successful</h2>
        <p>Redirecting to application...</p>
    </body>
    </html>
    """
    
    return HttpResponseRedirect(f"http://localhost:3000/auth?code={code}")

# Get current user profile endpoint
@router.get("/me", response=UserProfileSchema, auth=JWTAuth())
def get_profile(request):
    """Get the current user's profile"""
    try:
        user_id = request.auth.get('user_id')
        if not user_id:
            return JsonResponse({'detail': 'Invalid token'}, status=401)
        
        user = User.objects.get(id=user_id)
        return {
            'user_id': user.id,
            'email': user.email,
            'name': f"{user.first_name} {user.last_name}".strip(),
            'asal_sekolah': user.profile.asal_sekolah,
        }
    except User.DoesNotExist:
        return JsonResponse({'detail': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'detail': str(e)}, status=500)

# Update user profile endpoint
@router.put("/me/profile", response=UserProfileSchema, auth=JWTAuth())
def update_profile(request, profile_data: ProfileUpdateSchema):
    """Update the current user's profile (asal_sekolah)"""
    print(f"Updating profile for user {request.auth.get('user_id')}")
    try:
        user_id = request.auth.get('user_id')
        if not user_id:
            return JsonResponse({'detail': 'Invalid token'}, status=401)
        
        user = User.objects.get(id=user_id)
        if profile_data.name is None and profile_data.asal_sekolah is None:
            return JsonResponse({'detail': 'No fields to update'}, status=400)
        # Split and assign name to first_name and last_name if provided
        if profile_data.name:
            name_parts = profile_data.name.split()
            if len(name_parts) > 1:
                user.first_name = name_parts[0]
                user.last_name = ' '.join(name_parts[1:])
            else:
                user.first_name = profile_data.name
                user.last_name = ''
            user.save()
       
        user.profile.asal_sekolah = profile_data.asal_sekolah if profile_data.asal_sekolah else user.profile.asal_sekolah
        user.profile.save()

        ActivityLog.objects.create(
            user=user,
            action="update_profile",
            details=f"Updated profile: {profile_data.dict()}"
        )
        return {
            'user_id': user.id,
            'email': user.email,
            'name': f"{user.first_name} {user.last_name}".strip(),
            'asal_sekolah': user.profile.asal_sekolah,
        }
    except User.DoesNotExist:
        return JsonResponse({'detail': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'detail': str(e)}, status=500) 