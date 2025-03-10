from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth.hashers import check_password
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from .serializers import UserRegisterSerializer, UserProfileSerializer
from .models import CustomUser
from .utils import send_email_otp, send_sms_otp
from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404, render
from users.models import CustomUser
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.contrib.auth import login
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import update_last_login
from users.models import CustomUser
from rest_framework.views import APIView


User = get_user_model()

def home(request):

    return render(request, 'index.html')




def profile_view(request):
    user_id = request.session.get("user_id")  # ✅ Fetch user ID from session

    if not user_id:
        return HttpResponse("Error: User not authenticated!", status=401)

    try:
        user = CustomUser.objects.get(id=user_id)  # ✅ Fetch user by ID
        print("User Email:", user.email)


        return render(request, "profile.html", {"user": user})

    except CustomUser.DoesNotExist:
        print("Error: User not found")
        return HttpResponse("Error: User not found", status=404)


def get_user_profile(request):
    """Fetch user details and return JSON response"""
    user = request.user  # ✅ Automatically fetches authenticated user

    print("📌 Fetching user profile for:", user.email)  # Debugging
    print("✅ User details before sending JSON response:")

    profile_data = {
        "email": user.email,
        "mobile": getattr(user, "mobile", ""),  # Avoid AttributeError
        "username": user.username or "",
        "full_name": user.full_name or "",
        "bio": user.bio or "",
        "profile_picture": user.profile_picture.url if user.profile_picture else None,
        "is_active": user.is_active,
        "is_admin": user.is_admin,
    }

    print(profile_data)  # Debugging
    return JsonResponse({"data": profile_data}, safe=False)
class UserRegistrationView(APIView):
    """Registers a user and sends OTP to email and mobile"""

    def post(self, request):
        print("Received Data:", request.data)  # Debugging line

        email = request.data.get("email")
        mobile = request.data.get("mobile")

        if CustomUser.objects.filter(email=email).exists():
            return Response({"error": "A user with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(mobile=mobile).exists():
            return Response({"error": "A user with this mobile number already exists."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_email_otp(user.email, user.email_otp)
            send_sms_otp(user.mobile, user.mobile_otp, "att")
            return Response({"message": "OTP sent to email and mobile. Please verify."}, status=status.HTTP_201_CREATED)

        print("Serializer Errors:", serializer.errors)  # Debugging line
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyOTPView(APIView):
    """Verifies OTP for email and mobile"""

    def post(self, request):
        email = request.data.get("email")
        mobile = request.data.get("mobile")
        email_otp = request.data.get("email_otp")
        mobile_otp = request.data.get("mobile_otp")

        user = get_object_or_404(CustomUser, email=email, mobile=mobile)

        if user.email_otp == email_otp and user.mobile_otp == mobile_otp:
            user.is_active = True
            user.email_otp = None
            user.mobile_otp = None
            user.save()

            return Response({"message": "Verification successful. Now login to continue."}, status=status.HTTP_200_OK)

        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """Login user with email and password"""

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = CustomUser.objects.get(email=email)  # Fetch user by email
            print(f"User found: {user} (Type: {type(user)})")
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        if not check_password(password, user.password):  # Verify password
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({"error": "Account not verified. Please verify OTP."}, status=status.HTTP_403_FORBIDDEN)

        # ✅ Log the user in and set session
        login(request, user)
        update_last_login(None, user)  # Optional: Update last login time

        request.session["user_id"] = user.id  # ✅ Store user ID in session
        request.session.save()  # ✅ Ensure session is saved

        return Response(
            {"message": "Login successful", "email": user.email},
            status=status.HTTP_200_OK
        )



class UserProfileView(APIView):
    """View for retrieving and updating user profiles"""
    parser_classes = [MultiPartParser, FormParser]  # Enables image uploads

    def get(self, request):
        """Retrieve user profile"""
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(
            {"message": "Profile retrieved successfully", "data": serializer.data},
            status=status.HTTP_200_OK
        )

    def put(self, request):
        """Update profile details"""
        user = request.user
        serializer = UserProfileSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Profile updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK
            )

        return Response(
            {"error": "Invalid data", "details": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST
        )
