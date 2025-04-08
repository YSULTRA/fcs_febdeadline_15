from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, FormParser
from django.contrib.auth.hashers import check_password
from django.contrib.auth import authenticate
from django.shortcuts import get_object_or_404
from .serializers import UserRegisterSerializer, UserProfileSerializer
from .models import CustomUser
from django.views.decorators.http import require_POST
from decimal import Decimal
from django.utils import timezone
from django.http import HttpResponseRedirect
from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import redirect
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
from .models import *
logger = logging.getLogger(__name__)




def verify_signature(self):
    public_key = self.sender.get_public_key()
    message_data = (self.text_encrypted or "").encode('utf-8')
    signature = bytes.fromhex(self.signature or "")
    try:
        public_key.verify(
            signature,
            message_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False






@csrf_exempt
def send_message(request):
    if request.method == 'POST':
        sender_email = request.POST.get("sender")
        receiver_email = request.POST.get("receiver")
        text = request.POST.get("text", "")
        media_file = request.FILES.get("media")

        if sender_email and receiver_email:
            sender = get_object_or_404(CustomUser, email=sender_email)
            receiver = get_object_or_404(CustomUser, email=receiver_email)

            # Ensure sender has a key pair
            if not sender.public_key or not sender.private_key_encrypted:
                sender.generate_key_pair()

            message = Message(sender=sender, receiver=receiver, text_encrypted=text if text else "")
            if media_file:
                message.media = media_file
                print(f"Received media: {media_file.name}")

            # Encrypt and sign the message
            if text:
                message.text_encrypted = message.encrypt_message(text)
            message.sign_message()
            message.save()

            return JsonResponse({
                "status": "Message sent",
                "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            })
        else:
            return JsonResponse({"error": "Sender and receiver are required"}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)




@csrf_exempt
def get_messages(request):
    sender_email = request.GET.get('sender')
    receiver_email = request.GET.get('receiver')

    if not sender_email or not receiver_email:
        return JsonResponse({"error": "Sender and receiver emails required"}, status=400)

    sender = get_object_or_404(CustomUser, email=sender_email)
    receiver = get_object_or_404(CustomUser, email=receiver_email)

    # Check if sender has blocked receiver
    block = Block.objects.filter(blocker=sender, blocked_user=receiver).first()
    blocked_users = Block.objects.filter(blocker=sender).values_list('blocked_user__email', flat=True)

    messages = Message.objects.filter(
        (Q(sender__email=sender_email) & Q(receiver__email=receiver_email)) |
        (Q(sender__email=receiver_email) & Q(receiver__email=sender_email))
    ).exclude(sender__email__in=blocked_users).exclude(sender__is_active=False)

    # If sender has blocked receiver, filter messages to those before the block
    if block:
        messages = messages.filter(timestamp__lt=block.blocked_at)

    messages = messages.order_by("timestamp")

    messages_list = []
    for msg in messages:
        is_valid = msg.verify_signature()
        msg_data = {
            "id": msg.id,
            "sender": msg.sender.email,
            "receiver": msg.receiver.email,
            "text": msg.decrypt_message() if msg.text_encrypted else "",
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "signature_valid": is_valid
        }
        if msg.media:
            msg_data["media_url"] = f"/serve-media/{msg.id}/"
            msg_data["media_type"] = msg.media.name.split('.')[-1]
        messages_list.append(msg_data)

    # Add blocked status to response
    is_blocked = block is not None
    return JsonResponse({"messages": messages_list, "is_blocked": is_blocked}, safe=False)

@csrf_exempt
def serve_media(request, message_id):
    print(f"Attempting to serve media for message ID: {message_id}")
    message = get_object_or_404(Message, id=message_id)
    if message.media:
        print(f"Media found: {message.media.name}")
        decrypted_content = message.decrypt_media()
        if decrypted_content:
            print(f"Decrypted content length: {len(decrypted_content)} bytes")
            media_type = message.media.name.split('.')[-1]
            content_type = (
                "image/jpeg" if media_type in ["jpeg", "jpg"] else
                "image/png" if media_type == "png" else
                "video/mp4" if media_type == "mp4" else
                "application/octet-stream"
            )
            return HttpResponse(decrypted_content, content_type=content_type)
        else:
            print("Decryption failed")
            return HttpResponse("Decryption failed", status=500)
    else:
        print("No media found for this message")
    return HttpResponse("Media not found", status=404)



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
    sender_email = request.session.get("user_email")
    receiver_email = request.GET.get('receiver')
    receiver = None
    if not sender_email:
        return render(request, "chat.html", {"error": "User not logged in."})
    if receiver_email:
        try:
            receiver = CustomUser.objects.get(email=receiver_email)
        except CustomUser.DoesNotExist:
            receiver = None
    sender = get_object_or_404(CustomUser, email=sender_email)
    users = CustomUser.objects.all()
    # Fetch blocked users for the sender
    blocked_users = Block.objects.filter(blocker=sender).values_list('blocked_user__email', flat=True)
    print("Sender:", sender.email, "Blocked Users:", blocked_users)  # Debug output
    return render(request, "chat.html", {
        "users": users,
        "sender": sender,
        "receiver": receiver,
        "blocked_users": blocked_users
    })



def sign_existing_messages():
    messages = Message.objects.filter(signature__isnull=True)
    for msg in messages:
        if msg.text_encrypted:
            msg.sign_message()
            msg.save()
    print(f"Signed {messages.count()} messages")

@csrf_exempt
def home(request):

    return render(request, 'index.html')


# In your views.py

# In users/views.py
@csrf_exempt
def create_group(request):
    if request.method == "POST":
        sender_email = request.POST.get("sender") or request.session.get("user_email")
        group_name = request.POST.get("group_name")
        member_emails = request.POST.getlist("members")

        if not sender_email:
            return JsonResponse({"error": "Sender email is required"}, status=400)

        sender = get_object_or_404(CustomUser, email=sender_email)

        # Check if user is verified by admin
        if not sender.is_verified_by_admin:
            # For unverified users, group_name and members are not required
            existing_request = GroupCreationRequest.objects.filter(user=sender, approved__isnull=True).exists()
            if existing_request:
                return JsonResponse({"error": "You already have a pending group creation request."}, status=403)

            # Create a new request
            GroupCreationRequest.objects.create(user=sender)
            return JsonResponse({"status": "Group creation request sent to admin for approval."}, status=201)

        # For verified users, group_name is required
        if not group_name:
            return JsonResponse({"error": "Group name is required for verified users"}, status=400)

        # If verified, proceed with group creation
        group = Group.objects.create(name=group_name, creator=sender)
        group.members.add(sender)

        for email in member_emails:
            try:
                member = CustomUser.objects.get(email=email)
                group.members.add(member)
            except CustomUser.DoesNotExist:
                continue

        return JsonResponse({"status": "Group created", "group_id": group.id}, status=201)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def send_group_message(request):
    if request.method == "POST":
        sender_email = request.POST.get("sender")
        group_id = request.POST.get("group_id")
        text = request.POST.get("text", "")
        media_file = request.FILES.get("media")

        if not sender_email or not group_id:
            return JsonResponse({"error": "Sender and group ID are required"}, status=400)

        sender = get_object_or_404(CustomUser, email=sender_email)
        group = get_object_or_404(Group, id=group_id)

        if sender not in group.members.all():
            return JsonResponse({"error": "Sender is not a member of this group"}, status=403)

        if not sender.public_key or not sender.private_key_encrypted:
            sender.generate_key_pair()

        message = GroupMessage(group=group, sender=sender)
        if media_file:
            message.media = media_file
            print(f"Received group media: {media_file.name}")

        if text:
            # Always encrypt the text (remove the optional condition if encryption is mandatory)
            message.text_encrypted = message.encrypt_message(text)
        else:
            message.text_encrypted = ""

        message.sign_message()  # Generate signature
        message.save()

        return JsonResponse({
            "status": "Group message sent",
            "timestamp": message.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_group_messages(request):
    group_id = request.GET.get("group_id")
    sender_email = request.session.get("user_email")

    if not group_id or not sender_email:
        return JsonResponse({"error": "Group ID and sender email required"}, status=400)

    group = get_object_or_404(Group, id=group_id)
    sender = get_object_or_404(CustomUser, email=sender_email)

    if sender not in group.members.all():
        return JsonResponse({"error": "You are not a member of this group"}, status=403)

    blocked_users = Block.objects.filter(blocker=sender).values_list('blocked_user__email', flat=True)
    messages = GroupMessage.objects.filter(group=group).exclude(sender__email__in=blocked_users).exclude(sender__is_active=False).order_by("timestamp")

    messages_list = []
    for msg in messages:
        is_valid = msg.verify_signature()
        msg_data = {
            "id": msg.id,
            "sender": msg.sender.email,
            "text": msg.decrypt_message(),
            "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "signature_valid": is_valid
        }
        if msg.media:
            msg_data["media_url"] = f"/serve-group-media/{msg.id}/"
            msg_data["media_type"] = msg.media.name.split('.')[-1]
        messages_list.append(msg_data)

    return JsonResponse({"messages": messages_list}, safe=False)

@csrf_exempt
def serve_group_media(request, message_id):
    print(f"Attempting to serve group media for message ID: {message_id}")
    message = get_object_or_404(GroupMessage, id=message_id)
    if message.media:
        print(f"Media found: {message.media.name}")
        decrypted_content = message.decrypt_media()
        if decrypted_content:
            print(f"Decrypted content length: {len(decrypted_content)} bytes")
            media_type = message.media.name.split('.')[-1]
            content_type = (
                "image/jpeg" if media_type in ["jpeg", "jpg"] else
                "image/png" if media_type == "png" else
                "video/mp4" if media_type == "mp4" else
                "application/octet-stream"
            )
            return HttpResponse(decrypted_content, content_type=content_type)
        else:
            print("Decryption failed")
            return HttpResponse("Decryption failed", status=500)
    else:
        print("No media found for this message")
    return HttpResponse("Media not found", status=404)

@csrf_exempt
def group_chat_view(request):
    sender_email = request.session.get("user_email")
    if not sender_email:
        return render(request, "group_chat.html", {"error": "User not logged in."})

    sender = get_object_or_404(CustomUser, email=sender_email)
    groups = Group.objects.filter(members=sender)  # Fetch groups the sender is a member of

    return render(request, "group_chat.html", {"sender": sender, "groups": groups})

@csrf_exempt
def get_private_key(request):
    email = request.session.get("user_email")
    user = get_object_or_404(CustomUser, email=email)
    private_key = user.get_private_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return JsonResponse({"private_key": pem.decode('utf-8')})

# In users/views.py
@csrf_exempt
def manage_group_requests(request):
    if request.method == "GET":
        # Only admins can view requests
        sender_email = request.session.get("user_email")
        sender = get_object_or_404(CustomUser, email=sender_email)
        if not sender.is_admin:
            return JsonResponse({"error": "Only admins can view group creation requests."}, status=403)

        requests = GroupCreationRequest.objects.filter(approved__isnull=True)
        request_list = [
            {
                "id": req.id,
                "user_email": req.user.email,
                "requested_at": req.requested_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for req in requests
        ]
        return JsonResponse({"requests": request_list})

    elif request.method == "POST":
        sender_email = request.session.get("user_email")
        sender = get_object_or_404(CustomUser, email=sender_email)
        if not sender.is_admin:
            return JsonResponse({"error": "Only admins can approve group creation requests."}, status=403)

        request_id = request.POST.get("request_id")
        action = request.POST.get("action")

        req = get_object_or_404(GroupCreationRequest, id=request_id)
        if action == "approve":
            req.approved = True
            req.user.is_verified_by_admin = True  # This sets the user as verified
            req.user.save()
            req.reviewed_at = timezone.now()
            req.save()
            return JsonResponse({"status": f"Request by {req.user.email} approved."})
        elif action == "reject":
            req.approved = False
            req.reviewed_at = timezone.now()
            req.save()
            return JsonResponse({"status": f"Request by {req.user.email} rejected."})
        else:
            return JsonResponse({"error": "Invalid action. Use 'approve' or 'reject'."}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

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
    if not user_id:
        return HttpResponse("Error: User not authenticated!", status=401)

    try:
        user = CustomUser.objects.get(id=user_id)
        wallet = get_or_create_wallet(user)  # From previous wallet implementation

        if request.method == 'POST':
            if 'topup_amount' in request.POST:
                # Handle wallet top-up
                amount = request.POST.get('topup_amount')
                try:
                    amount = Decimal(amount)
                    if amount <= 0:
                        messages.error(request, "Amount must be positive!")
                    else:
                        wallet.balance += amount
                        wallet.save()
                        Transaction.objects.create(
                            sender=user,
                            receiver=user,
                            amount=amount,
                            is_topup=True
                        )
                        messages.success(request, f"Wallet topped up by ${amount}!")
                except ValueError:
                    messages.error(request, "Invalid amount!")
                return redirect('user-profile')
            else:
                # Handle profile update
                form = ProfileUpdateForm(request.POST, request.FILES, instance=user)
                if form.is_valid():
                    form.save()
                    messages.success(request, "Profile updated successfully!")
                    return redirect('user-profile')
                else:
                    messages.error(request, "Error updating profile. Please check the form.")
        else:
            form = ProfileUpdateForm(instance=user)

        # Fetch purchased and listed products
        purchased_products = Product.objects.filter(
            transaction__sender=user, transaction__product__isnull=False
        ).prefetch_related('transaction_set').distinct()
        listed_products = Product.objects.filter(seller=user)


        for product in purchased_products:
            print(f"Product: {product.title}, Price: {product.price}, Seller: {product.seller.email}")
            if product.transaction_set.exists():
                print(f"Transaction: {product.transaction_set.first().timestamp}")
            else:
                print(f"No transactions for {product.title}")

        return render(request, "profile.html", {
            "user": user,
            "form": form,
            "wallet_balance": wallet.balance,
            "purchased_products": purchased_products,
            "listed_products": listed_products
        })

    except CustomUser.DoesNotExist:
        messages.error(request, "User not found.")
        return HttpResponse("Error: User not found", status=404)
@csrf_exempt
def get_user_profile(request):
    """Fetch user details and return JSON response"""
    sender_email = request.session.get("user_email")
    if not sender_email:
        print("📌 No user email found in session")
        return JsonResponse({"error": "User not logged in"}, status=401)

    user = get_object_or_404(CustomUser, email=sender_email)

    print("📌 Fetching user profile for:", user.email)
    profile_data = {
        "email": user.email,
        "mobile": getattr(user, "mobile", ""),
        "username": user.username or "",
        "full_name": user.full_name or "",
        "bio": user.bio or "",
        "profile_picture": user.profile_picture.url if user.profile_picture else None,
        "is_active": user.is_active,
        "is_admin": user.is_admin,
        "is_verified_by_admin": user.is_verified_by_admin,
    }
    print(profile_data)
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
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        mobile = request.data.get("mobile")
        email_otp = request.data.get("email_otp")
        mobile_otp = request.data.get("mobile_otp")
        action = request.data.get("action")

        user = get_object_or_404(CustomUser, email=email, mobile=mobile)

        high_risk_actions = ["password_reset", "account_closure"]
        if action in high_risk_actions and (not email_otp or not mobile_otp):
            return Response({"error": "OTP required for high-risk actions"}, status=status.HTTP_400_BAD_REQUEST)

        if user.email_otp == email_otp and user.mobile_otp == mobile_otp:
            user.is_active = True
            user.email_otp = None
            user.mobile_otp = None
            user.save()

            # Return private key in PEM format
            private_key = user.get_private_key()
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')

            return Response({
                "message": f"Verification successful for {action or 'login'}. Proceed accordingly.",
                "private_key": private_key_pem
            }, status=status.HTTP_200_OK)

        return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    permission_classes = [AllowAny]  # AllowAny

    def get(self, request):
        """Render login page for GET requests"""
        return render(request, "index.html")
    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        challenge = request.data.get("challenge")
        signature = request.data.get("signature")

        user = get_object_or_404(CustomUser, email=email)
        if not user.check_password(password):
            return Response({"error": "Invalid email or password"}, status=status.HTTP_401_UNAUTHORIZED)

        if not user.is_active:
            return Response({"error": "Account not verified"}, status=status.HTTP_403_FORBIDDEN)

        # PKI verification if challenge and signature provided
        if challenge and signature:
            public_key = user.get_public_key()
            try:
                public_key.verify(
                    bytes.fromhex(signature),
                    challenge.encode('utf-8'),
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                    hashes.SHA256()
                )
            except Exception:
                return Response({"error": "Invalid signature"}, status=status.HTTP_401_UNAUTHORIZED)

        login(request, user)
        request.session["user_id"] = user.id
        request.session["user_email"] = user.email
        request.session["auth_challenge"] = secrets.token_hex(16)  # Generate challenge
        request.session.save()

        return Response({
            "message": "Login successful",
            "user_email": user.email,
            "challenge": request.session["auth_challenge"]
        }, status=status.HTTP_200_OK)


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



@method_decorator(csrf_exempt, name='dispatch')
class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        user = get_object_or_404(CustomUser, email=email)

        # Generate and send OTP
        user.email_otp = user.generate_otp()
        user.mobile_otp = user.generate_otp()
        user.save()
        send_email_otp(user.email, user.email_otp)
        send_sms_otp(user.email, user.mobile, user.mobile_otp, "att")

        return Response({"message": "OTP sent for password reset. Verify using virtual keyboard."}, status=status.HTTP_200_OK)


@method_decorator(csrf_exempt, name='dispatch')
class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        email_otp = request.data.get("email_otp")
        mobile_otp = request.data.get("mobile_otp")
        new_password = request.data.get("new_password")

        user = CustomUser.objects.filter(email=email).first()
        if not user:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        if user.email_otp != email_otp or user.mobile_otp != mobile_otp:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)

        # Update password
        user.set_password(new_password)
        user.email_otp = None
        user.mobile_otp = None
        user.save()

        return Response({"message": "Password reset successful. Please log in."}, status=status.HTTP_200_OK)


@csrf_exempt
def request_account_deactivation(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        print(f"DEBUG: request_account_deactivation - sender_email={sender_email}")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        user = get_object_or_404(CustomUser, email=sender_email)
        if AccountDeactivationRequest.objects.filter(user=user, approved__isnull=True).exists():
            return JsonResponse({"error": "You already have a pending deactivation request"}, status=403)

        # Generate OTPs
        user.email_otp = user.generate_otp()
        user.mobile_otp = user.generate_otp()
        user.save()
        print(f"DEBUG: Generated OTPs - email_otp={user.email_otp}, mobile_otp={user.mobile_otp}")

        # Send OTPs
        send_email_otp(user.email, user.email_otp)
        send_sms_otp(user.email, user.mobile, user.mobile_otp, "att")

        # Create deactivation request
        AccountDeactivationRequest.objects.create(user=user)
        return JsonResponse({"message": "OTP sent. Request pending admin approval."}, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def confirm_account_deactivation(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        print(f"DEBUG: confirm_account_deactivation - sender_email={sender_email}")
        print(f"DEBUG: confirm_account_deactivation - Raw request.body={request.body}")

        try:
            data = json.loads(request.body.decode('utf-8'))
            email_otp = data.get("email_otp")
            mobile_otp = data.get("mobile_otp")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"DEBUG: Error parsing request.body - {str(e)}")
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        print(f"DEBUG: Parsed email_otp={email_otp}, mobile_otp={mobile_otp}")

        if not sender_email or not email_otp or not mobile_otp:
            return JsonResponse({"error": "Missing required fields"}, status=400)

        user = get_object_or_404(CustomUser, email=sender_email)
        print(f"DEBUG: User OTPs - stored email_otp={user.email_otp}, stored mobile_otp={user.mobile_otp}")
        if user.email_otp != email_otp or user.mobile_otp != mobile_otp:
            return JsonResponse({"error": "Invalid OTP"}, status=400)

        user.email_otp = None
        user.mobile_otp = None
        user.save()

        return JsonResponse({"message": "OTP verified. Awaiting admin approval."}, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def confirm_report(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        if not sender_email:
            return JsonResponse({"error": "Authentication required"}, status=401)

        try:
            data = json.loads(request.body)
            report_id = data.get("report_id")
            email_otp = data.get("email_otp")
            mobile_otp = data.get("mobile_otp")
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        if not report_id or not email_otp or not mobile_otp:
            return JsonResponse({"error": "Report ID and OTPs are required"}, status=400)

        reporter = get_object_or_404(CustomUser, email=sender_email)
        report = get_object_or_404(Report, id=report_id, reporter=reporter, reviewed=False)

        if reporter.email_otp != email_otp or reporter.mobile_otp != mobile_otp:
            return JsonResponse({"error": "Invalid OTP"}, status=400)

        # Clear OTPs
        reporter.email_otp = None
        reporter.mobile_otp = None
        reporter.save()

        return JsonResponse({
            "status": "success",
            "message": "Report confirmed. Awaiting admin approval."
        })
    return JsonResponse({"error": "Invalid request method"}, status=405)



@csrf_exempt
def request_account_deletion(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        print(f"DEBUG: request_account_deletion - sender_email={sender_email}")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        user = get_object_or_404(CustomUser, email=sender_email)
        if AccountDeletionRequest.objects.filter(user=user, approved__isnull=True).exists():
            return JsonResponse({"error": "You already have a pending deletion request"}, status=403)

        # Generate OTPs
        user.email_otp = user.generate_otp()
        user.mobile_otp = user.generate_otp()
        user.save()
        print(f"DEBUG: Generated OTPs - email_otp={user.email_otp}, mobile_otp={user.mobile_otp}")

        # Send OTPs
        send_email_otp(user.email, user.email_otp)
        send_sms_otp(user.email, user.mobile, user.mobile_otp, "att")

        # Create deletion request
        AccountDeletionRequest.objects.create(user=user)
        return JsonResponse({"message": "OTP sent. Request pending admin approval."}, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def confirm_account_deletion(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        print(f"DEBUG: confirm_account_deletion - sender_email={sender_email}")
        print(f"DEBUG: confirm_account_deletion - Raw request.body={request.body}")

        try:
            data = json.loads(request.body.decode('utf-8'))
            email_otp = data.get("email_otp")
            mobile_otp = data.get("mobile_otp")
        except (json.JSONDecodeError, ValueError) as e:
            print(f"DEBUG: Error parsing request.body - {str(e)}")
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        print(f"DEBUG: Parsed email_otp={email_otp}, mobile_otp={mobile_otp}")

        if not sender_email or not email_otp or not mobile_otp:
            return JsonResponse({"error": "Missing required fields"}, status=400)

        user = get_object_or_404(CustomUser, email=sender_email)
        print(f"DEBUG: User OTPs - stored email_otp={user.email_otp}, stored mobile_otp={user.mobile_otp}")
        if user.email_otp != email_otp or user.mobile_otp != mobile_otp:
            return JsonResponse({"error": "Invalid OTP"}, status=400)

        user.email_otp = None
        user.mobile_otp = None
        user.save()

        return JsonResponse({"message": "OTP verified. Awaiting admin approval."}, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=405)



@csrf_exempt
def report_message(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        print(f"DEBUG: report_message - sender_email={sender_email}")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        try:
            data = json.loads(request.body.decode('utf-8'))
            print(f"DEBUG: report_message - Raw request.body={request.body}")
            message_id = data.get("message_id")
            reason = data.get("reason")
            is_group = data.get("is_group", False)
        except (json.JSONDecodeError, ValueError) as e:
            print(f"DEBUG: Error parsing request.body - {str(e)}")
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        if not message_id or not reason:
            return JsonResponse({"error": "Message ID and reason are required"}, status=400)

        reporter = get_object_or_404(CustomUser, email=sender_email)

        # Fetch the message (group or private)
        if is_group:
            message = get_object_or_404(GroupMessage, id=message_id)
            if reporter not in message.group.members.all():
                return JsonResponse({"error": "You are not a member of this group"}, status=403)
            reported_user = message.sender
        else:
            message = get_object_or_404(Message, id=message_id)
            if reporter not in [message.sender, message.receiver]:
                return JsonResponse({"error": "You cannot report this message"}, status=403)
            if message.sender == reporter:
                return JsonResponse({"error": "You cannot report your own message"}, status=403)
            reported_user = message.sender

        # Check for existing pending report
        if Report.objects.filter(
            reporter=reporter,
            message=message if not is_group else None,
            group_message=message if is_group else None,
            reviewed=False
        ).exists():
            return JsonResponse({"error": "You already have a pending report for this message"}, status=403)

        # Generate OTPs
        reporter.email_otp = reporter.generate_otp()
        reporter.mobile_otp = reporter.generate_otp()
        reporter.save()
        print(f"DEBUG: Generated OTPs - email_otp={reporter.email_otp}, mobile_otp={reporter.mobile_otp}")

        # Send OTPs
        try:
            send_email_otp(reporter.email, reporter.email_otp)
            send_sms_otp(reporter.email, reporter.mobile, reporter.mobile_otp, "att")
            print(f"DEBUG: OTPs sent to {reporter.email} and {reporter.mobile}")
        except Exception as e:
            logger.error(f"Error sending OTPs: {str(e)}", exc_info=True)
            return JsonResponse({"error": "Failed to send OTPs"}, status=500)

        # Create report request
        report = Report.objects.create(
            reporter=reporter,
            message=message if not is_group else None,
            group_message=message if is_group else None,
            reason=reason
        )
        print(f"DEBUG: Report created - report_id={report.id}")

        return JsonResponse({
            "message": "OTP sent. Request pending admin approval.",
            "report_id": report.id
        }, status=200)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def block_user(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        if not sender_email:
            return JsonResponse({"error": "Authentication required"}, status=401)

        try:
            data = json.loads(request.body)
            blocked_email = data.get("blocked_user")
            blocker = get_object_or_404(CustomUser, email=sender_email)
            blocked_user = get_object_or_404(CustomUser, email=blocked_email)

            if blocker.email == blocked_email:
                return JsonResponse({"error": "You cannot block yourself"}, status=400)

            # Create or get block relationship
            block, created = Block.objects.get_or_create(blocker=blocker, blocked_user=blocked_user)
            if created:
                return JsonResponse({"status": "success", "message": f"Blocked {blocked_email}"})
            else:
                return JsonResponse({"status": "success", "message": f"{blocked_email} was already blocked"})
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)
        except CustomUser.DoesNotExist:
            return JsonResponse({"error": "User to block not found"}, status=404)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)


@staff_member_required
def admin_reports(request):
    reports = Report.objects.filter(reviewed=False).order_by('-reported_at')
    return render(request, 'admin_reports.html', {'reports': reports})

@staff_member_required
@require_POST
def review_report(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    action = request.POST.get("action")

    if action == "ban_user":
        user_to_ban = report.message.sender if report.message else report.group_message.sender
        user_to_ban.is_active = False  # Deactivate user
        user_to_ban.save()
        # Remove from groups
        Group.objects.filter(members=user_to_ban).update(members=models.F('members').remove(user_to_ban))
        report.action_taken = "User banned"
    elif action == "delete_message":
        if report.message:
            report.message.delete()
        else:
            report.group_message.delete()
        report.action_taken = "Message deleted"
    else:
        report.action_taken = "Dismissed"

    report.reviewed = True
    report.save()
    return redirect('admin_reports')


@staff_member_required
def ban_user(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    if not report.reviewed:
        user_to_ban = report.message.sender if report.message else report.group_message.sender
        user_to_ban.is_active = False
        user_to_ban.save()
        Group.objects.filter(members=user_to_ban).update(members=models.F('members').remove(user_to_ban))
        report.action_taken = "User banned"
        report.reviewed = True
        report.save()
    return HttpResponseRedirect(reverse('admin:users_report_changelist'))

@staff_member_required
def delete_message(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    if not report.reviewed:
        if report.message:
            report.message.delete()
        elif report.group_message:
            report.group_message.delete()
        report.action_taken = "Message deleted"
        report.reviewed = True
        report.save()
    return HttpResponseRedirect(reverse('admin:users_report_changelist'))

@staff_member_required
def dismiss_report(request, report_id):
    report = get_object_or_404(Report, id=report_id)
    if not report.reviewed:
        report.action_taken = "Dismissed"
        report.reviewed = True
        report.save()
    return HttpResponseRedirect(reverse('admin:users_report_changelist'))



def marketplace_view(request):
    sender_email = request.session.get("user_email")
    if not sender_email:
        return render(request, "marketplace.html", {"error": "User not logged in."})
    return render(request, "marketplace.html")

# Ensure wallet exists for a user
def get_or_create_wallet(user):
    wallet, created = Wallet.objects.get_or_create(user=user)
    return wallet

# List a product
@csrf_exempt
def list_product(request):
    if request.method == "POST":
        user_email = request.session.get("user_email")
        if not user_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        try:
            user = CustomUser.objects.get(email=user_email)
            data = request.POST
            title = data.get("title")
            description = data.get("description", "")
            price = Decimal(data.get("price", 0))

            if not title or not price:
                return JsonResponse({"error": "Title and price are required"}, status=400)

            product = Product.objects.create(
                seller=user,
                title=title,
                description=description,
                price=price
            )

            if 'image' in request.FILES:
                product.image = request.FILES['image']
                product.save()

            return JsonResponse({"message": f"Product {title} listed successfully", "product_id": product.id}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

# Get all available products
@csrf_exempt
def get_products(request):
    if request.method == "GET":
        sender_email = request.session.get("user_email")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        # Fetch products that are not sold and not listed by the current user
        products = Product.objects.filter(is_sold=False).exclude(seller__email=sender_email).select_related('seller')
        product_list = [
            {
                "id": p.id,
                "title": p.title,
                "description": p.description,
                "price": float(p.price),
                "seller": p.seller.email,
                "image": p.image.url if p.image else None
            } for p in products
        ]
        return JsonResponse({"products": product_list}, status=200)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_your_products(request):
    if request.method == "GET":
        user_email = request.session.get("user_email")
        if not user_email:
            return JsonResponse({"error": "User not logged in"}, status=401)
        user = CustomUser.objects.get(email=user_email)
        products = Product.objects.filter(seller=user).select_related('seller')
        product_list = [
            {
                "id": p.id,
                "title": p.title,
                "description": p.description,
                "price": float(p.price),
                "is_sold": p.is_sold,
                "image": p.image.url if p.image else None
            } for p in products
        ]
        return JsonResponse({"products": product_list}, status=200)
    return JsonResponse({"error": "Invalid request method"}, status=405)
@csrf_exempt
def buy_product(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        try:
            data = json.loads(request.body)
            product_id = data.get("product_id")
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        if not product_id:
            return JsonResponse({"error": "Product ID is required"}, status=400)

        buyer = get_object_or_404(CustomUser, email=sender_email)
        product = get_object_or_404(Product, id=product_id, is_sold=False)
        seller = product.seller

        if buyer == seller:
            return JsonResponse({"error": "You cannot buy your own product"}, status=400)

        buyer_wallet = get_or_create_wallet(buyer)
        seller_wallet = get_or_create_wallet(seller)

        if buyer_wallet.balance < product.price:
            return JsonResponse({"error": "Insufficient wallet balance"}, status=400)

        # Simulate payment
        buyer_wallet.balance -= product.price
        seller_wallet.balance += product.price
        product.is_sold = True

        buyer_wallet.save()
        seller_wallet.save()
        product.save()

        # Record transaction
        transaction = Transaction.objects.create(
            sender=buyer,
            receiver=seller,
            amount=product.price,
            product=product
        )
        print(f"Transaction created: {transaction.id}, Product: {product.title}, Timestamp: {transaction.timestamp}")

        return JsonResponse({
            "message": f"Purchased {product.title} for ${product.price}",
            "new_balance": str(buyer_wallet.balance)
        }, status=200)
    return JsonResponse({"error": "Invalid request method"}, status=405)
# Top-up wallet (Payment Simulation)
@csrf_exempt
def topup_wallet(request):
    if request.method == "POST":
        sender_email = request.session.get("user_email")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        try:
            data = json.loads(request.body)
            amount = data.get("amount")
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)

        if not amount or float(amount) <= 0:
            return JsonResponse({"error": "Valid amount is required"}, status=400)

        user = get_object_or_404(CustomUser, email=sender_email)
        wallet = Wallet.objects.get_or_create(user=user)[0]
        wallet.balance += float(amount)
        wallet.save()

        Transaction.objects.create(
            sender=user,
            receiver=user,
            amount=float(amount),
            is_topup=True
        )

        return JsonResponse({
            "message": f"Wallet topped up by ${amount}",
            "new_balance": str(wallet.balance)
        }, status=200)
    return JsonResponse({"error": "Invalid request method"}, status=405)

# Get wallet balance
@csrf_exempt
def get_wallet_balance(request):
    if request.method == "GET":
        sender_email = request.session.get("user_email")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        user = get_object_or_404(CustomUser, email=sender_email)
        wallet = get_or_create_wallet(user)
        return JsonResponse({"balance": str(wallet.balance)}, status=200)
    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def get_your_products(request):
    if request.method == "GET":
        sender_email = request.session.get("user_email")
        if not sender_email:
            return JsonResponse({"error": "User not logged in"}, status=401)

        products = Product.objects.filter(seller__email=sender_email)
        product_list = [
            {
                "id": p.id,
                "title": p.title,
                "description": p.description,
                "price": str(p.price),
                "seller": p.seller.email,
                "is_sold": p.is_sold,
                "created_at": p.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for p in products
        ]
        return JsonResponse({"products": product_list}, safe=False)
    return JsonResponse({"error": "Invalid request method"}, status=405)