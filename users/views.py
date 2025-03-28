from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth.hashers import check_password
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from .serializers import UserRegisterSerializer, UserProfileSerializer
from .models import CustomUser
from django.db import models
from django.contrib import messages
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
from django.utils.decorators import method_decorator
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import check_password
from django.contrib.auth.models import update_last_login
from users.models import CustomUser
from rest_framework.views import APIView
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.db.models import Q
from .models import CustomUser
from django.contrib.auth.decorators import login_required
from .forms import ProfileUpdateForm
from django.contrib.auth import logout
User = get_user_model()
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
import json
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from .models import Message
from users.models import CustomUser
from rest_framework.decorators import api_view
import logging
from rest_framework.permissions import AllowAny
logger = logging.getLogger(__name__)

@csrf_exempt
def send_message(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        sender_email = data.get("sender")
        receiver_email = data.get("receiver")
        text = data.get("text")

        if sender_email and receiver_email and text:
            sender = get_object_or_404(CustomUser, email=sender_email)
            receiver = get_object_or_404(CustomUser, email=receiver_email)

            # Create and save the encrypted message
            message = Message(sender=sender, receiver=receiver, text_encrypted=text)
            message.save()

            return JsonResponse({"status": "Message sent", "timestamp": message.timestamp})
        else:
            return JsonResponse({"error": "All fields are required"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_messages(request):
    sender_email = request.GET.get('sender')
    receiver_email = request.GET.get('receiver')

    if not sender_email or not receiver_email:
        return JsonResponse({"error": "Sender and receiver required"}, status=400)

    # Fetch messages where sender and receiver match either way
    messages = Message.objects.filter(
        (Q(sender__email=sender_email) & Q(receiver__email=receiver_email)) |
        (Q(sender__email=receiver_email) & Q(receiver__email=sender_email))
    ).order_by("timestamp")

    # Format messages list
    messages_list = [
        {
            "sender": msg.sender.email,
            "receiver": msg.receiver.email,
            "text": msg.decrypt_message(),  # Decrypt the message text
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for msg in messages
    ]

    return JsonResponse({"messages": messages_list}, safe=False)

@csrf_exempt
def search_users(request):
    query = request.GET.get("q", "")
    users = CustomUser.objects.filter(email__icontains=query)[:10]
    return render(request, "chat.html", {"users": users})

@csrf_exempt
def get_user_by_username(request):
    username = request.GET.get("username", None)
    if not username:
        return JsonResponse({"error": "Username is required"}, status=400)

    try:
        user = CustomUser.objects.get(username=username)
        return JsonResponse({"id": user.id})
    except CustomUser.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

@csrf_exempt
def get_current_user(request):
    user_id = request.session.get("user_id", None)

    if not user_id:
        return JsonResponse({"error": "User ID not found in session"}, status=400)

    return JsonResponse({"id": user_id})
@csrf_exempt
def chat_view(request):
    # Fetch the sender's email from the session
    sender_email = request.session.get("user_email")
    receiver_email = request.GET.get('receiver')
    receiver = None
    if not sender_email:
        return render(request, "chat.html", {"error": "User not logged in."})
    if receiver_email:
        try:
            receiver = CustomUser.objects.get(email=receiver_email)
        except CustomUser.DoesNotExist:
            # Handle the case where the receiver does not exist
            receiver = None
    # Fetch the sender object
    sender = CustomUser.objects.get(email=sender_email)

    # Fetch all users
    users = CustomUser.objects.all()

    # Debugging: Print the sender's email
    print("Sender:", sender.email)

    return render(request, "chat.html", {"users": users, "sender": sender,'receiver': receiver})



@csrf_exempt
def home(request):

    return render(request, 'index.html')
@method_decorator(csrf_exempt, name='dispatch')
class UserLogoutView(APIView):
    """Logs out the user by clearing session data"""
    permission_classes = [AllowAny]

    def post(self, request):
        user_id = request.session.get("user_id")

        if not user_id:
            return Response({"error": "User not logged in"}, status=status.HTTP_400_BAD_REQUEST)

        request.session.flush()  # ✅ Clears session data
        logout(request)  # ✅ Logs out the user

        # Add a success message
        messages.success(request, "Logout successful")

        # Redirect to the home page
        return redirect("home")
@csrf_exempt
def profile_view(request):
    user_id = request.session.get("user_id")
    permission_classes = [AllowAny]

    if not user_id:
        return HttpResponse("Error: User not authenticated!", status=401)

    try:
        user = CustomUser.objects.get(id=user_id)

        if request.method == 'POST':
            form = ProfileUpdateForm(request.POST, request.FILES, instance=user)
            if form.is_valid():
                form.save()
                messages.success(request, "Profile updated successfully!")  # Success message
                return redirect('user-profile')
            else:
                messages.error(request, "Error updating profile. Please check the form.")  # Error message
        else:
            form = ProfileUpdateForm(instance=user)

        return render(request, "profile.html", {"user": user, "form": form})

    except CustomUser.DoesNotExist:
        messages.error(request, "User not found.")  # Error message
        return HttpResponse("Error: User not found", status=404)
@csrf_exempt
def get_user_profile(request):
    """Fetch user details and return JSON response"""
    permission_classes = [AllowAny]

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

@method_decorator(csrf_exempt, name='dispatch')
class UserRegistrationView(APIView):
    """Registers a user and sends OTP to email and mobile"""
    permission_classes = [AllowAny]

    def post(self, request):
        print("Received Data:", request.data)  # Debugging line

        email = request.data.get("email")
        mobile = request.data.get("mobile")
        full_name = request.data.get("full_name")



        if not full_name:
            return Response({"error": "Full name is required."}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(email=email).exists():
            return Response({"error": "A user with this email already exists."}, status=status.HTTP_400_BAD_REQUEST)

        if CustomUser.objects.filter(mobile=mobile).exists():
            return Response({"error": "A user with this mobile number already exists."}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_email_otp(user.email, user.email_otp)
            send_sms_otp(user.email,user.mobile, user.mobile_otp, "att")
            return Response({
                "message": "OTP sent to email and mobile. Please verify.",
                "full_name": user.full_name  # Include full name in response
            }, status=status.HTTP_201_CREATED)

        print("Serializer Errors:", serializer.errors)  # Debugging line
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
@method_decorator(csrf_exempt, name='dispatch')
class VerifyOTPView(APIView):
    """Verifies OTP for email and mobile"""
    permission_classes = [AllowAny]

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

@method_decorator(csrf_exempt, name='dispatch')
class UserLoginView(APIView):
    """Login user with email and password"""
    permission_classes = [AllowAny]
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        if not check_password(password, user.password):
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({"error": "Account not verified. Please verify OTP."}, status=status.HTTP_403_FORBIDDEN)

        login(request, user)
        request.session["user_id"] = user.id
        request.session["user_email"] = user.email
        request.session.save()

        return Response({"message": "Login successful", "user_email": user.email}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class UserProfileView(APIView):
    """View for retrieving and updating user profiles"""
    permission_classes = [AllowAny]

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



