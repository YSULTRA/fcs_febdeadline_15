import random
import os
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager

def profile_picture_upload_path(instance, filename):
    """Generate unique path for profile pictures"""
    ext = filename.split('.')[-1]
    return f"profile_pictures/{instance.email}_{random.randint(1000,9999)}.{ext}"

class CustomUserManager(BaseUserManager):
    def create_user(self, email, mobile, password=None):
        if not email:
            raise ValueError("Users must have an email address")
        if not mobile:
            raise ValueError("Users must have a mobile number")

        user = self.model(email=self.normalize_email(email), mobile=mobile)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, mobile, password=None):
        user = self.create_user(email, mobile, password)
        user.is_admin = True
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
