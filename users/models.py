import random
import os
from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

def profile_picture_upload_path(instance, filename):
    """Generate unique path for profile pictures"""
    ext = filename.split('.')[-1]
    return f"profile_pictures/{instance.email}_{random.randint(1000,9999)}.{ext}"

class CustomUserManager(BaseUserManager):
    def create_user(self, email, mobile, password=None, full_name=None):
        if not email:
            raise ValueError("Users must have an email address")
        if not mobile:
            raise ValueError("Users must have a mobile number")

        user = self.model(
            email=self.normalize_email(email),
            mobile=mobile,
            full_name=full_name,  # Ensure full_name is properly assigned
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

class CustomUser(AbstractBaseUser):
    email = models.EmailField(unique=True)
    mobile = models.CharField(max_length=15, unique=True,null = True)
    username = models.CharField(max_length=50, unique=True, blank=True, null=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    bio = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to=profile_picture_upload_path, blank=True, null=True)
    # auth_token = models.CharField(max_length=500, null=True, blank=True)
    is_active = models.BooleanField(default=False)  # Only active after OTP verification
    is_admin = models.BooleanField(default=False)
    email_otp = models.CharField(max_length=6, blank=True, null=True)
    mobile_otp = models.CharField(max_length=6, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'


    def __str__(self):
        return self.email

    def generate_otp(self):
        return str(random.randint(100000, 999999))  # 6-digit OTP


# class Message(models.Model):
#     sender = models.ForeignKey(CustomUser, related_name="sent_messages", on_delete=models.CASCADE)
#     receiver = models.ForeignKey(CustomUser, related_name="received_messages", on_delete=models.CASCADE)
#     text = models.TextField()
#     timestamp = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"{self.sender.email} -> {self.receiver.email}: {self.text[:30]}"


class Message(models.Model):
    sender = models.ForeignKey("CustomUser", related_name="sent_messages", on_delete=models.CASCADE)
    receiver = models.ForeignKey("CustomUser", related_name="received_messages", on_delete=models.CASCADE)
    text_encrypted = models.TextField()  # Store encrypted text
    timestamp = models.DateTimeField(auto_now_add=True)

    def encrypt_message(self, message):
        """Encrypt message before saving."""
        cipher = Fernet(settings.ENCRYPTION_KEY.encode())  # Get encryption key from settings
        return cipher.encrypt(message.encode()).decode()

    def decrypt_message(self) -> str:
        """Decrypts the stored message."""
        if not self.text_encrypted:  # Handle empty encrypted text
            return ""
        try:
            cipher = Fernet(settings.ENCRYPTION_KEY.encode())
            return cipher.decrypt(self.text_encrypted.encode()).decode()
        except Exception as e:
            return "[Decryption Error]"

    def save(self, *args, **kwargs):
        """Encrypt message before saving, ensuring it is always stored encrypted."""
        if not self.pk or not self.text_encrypted.startswith("gAAAA"):  # Encrypt only if it's new or not encrypted
            self.text_encrypted = self.encrypt_message(self.text_encrypted)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.sender.email} -> {self.receiver.email}: [Encrypted]"