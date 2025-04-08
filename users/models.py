import random
import os,secrets
from django.db import models
from django.conf import settings
from cryptography.fernet import Fernet
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.core.files.base import ContentFile
from django.utils import timezone
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from django.core.validators import FileExtensionValidator


def message_media_upload_path(instance, filename):
    ext = filename.split('.')[-1]
    return f"message_media/{instance.sender.email}_{instance.id}_{random.randint(1000, 9999)}.{ext}"


def profile_picture_upload_path(instance, filename):
    """Generate unique path for profile pictures"""
    ext = filename.split('.')[-1]
    return f"profile_pictures/{instance.email}_{random.randint(1000,9999)}.{ext}"

class CustomUserManager(BaseUserManager):
    def create_user(self, email, mobile, password=None, full_name=None):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, mobile=mobile, full_name=full_name)
        user.set_password(password)
        user.save(using=self._db)
        user.generate_key_pair()  # Generate PKI keys on creation
        return user

    def create_superuser(self, email, mobile, password=None, full_name=None):
        user = self.create_user(email, mobile, password, full_name)
        user.is_admin = True
        user.is_active = True
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
    is_verified_by_admin = models.BooleanField(default=False)  # New field for admin verification
    email_otp = models.CharField(max_length=6, blank=True, null=True)
    mobile_otp = models.CharField(max_length=6, blank=True, null=True)

    public_key = models.TextField(blank=True, null=True)  # PEM-encoded public key
    private_key_encrypted = models.TextField(blank=True, null=True)  # Encrypted private key

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'


    def __str__(self):
        return self.email

    def generate_otp(self):
        return ''.join(secrets.choice('0123456789') for _ in range(6))

    def generate_key_pair(self):
        """Generate and store RSA key pair."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        cipher = Fernet(settings.ENCRYPTION_KEY.encode())
        encrypted_private_pem = cipher.encrypt(private_pem)

        self.public_key = public_pem.decode('utf-8')
        self.private_key_encrypted = encrypted_private_pem.decode('utf-8')
        self.save()

    def get_private_key(self):
        """Decrypt and return private key."""
        if not self.private_key_encrypted:
            self.generate_key_pair()
        cipher = Fernet(settings.ENCRYPTION_KEY.encode())
        decrypted_pem = cipher.decrypt(self.private_key_encrypted.encode('utf-8'))
        return serialization.load_pem_private_key(decrypted_pem, password=None)

    def get_public_key(self):
        """Return public key."""
        if not self.public_key:
            self.generate_key_pair()
        return serialization.load_pem_public_key(self.public_key.encode('utf-8'))


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
    text_encrypted = models.TextField(blank=True, null=True)  # Encrypted text (optional if media is present)
    media = models.FileField(upload_to=message_media_upload_path, blank=True, null=True)  # Media file (image/video)
    media_encrypted = models.BooleanField(default=False)  # Flag to indicate if media is encrypted
    timestamp = models.DateTimeField(auto_now_add=True)
    signature = models.TextField(blank=True, null=True)  # Store signature

    def encrypt_message(self, text):
        cipher = Fernet(settings.ENCRYPTION_KEY.encode())
        return cipher.encrypt(text.encode('utf-8')).decode('utf-8')

    def decrypt_message(self):
        if not self.text_encrypted:
            return ""
        cipher = Fernet(settings.ENCRYPTION_KEY.encode())
        return cipher.decrypt(self.text_encrypted.encode('utf-8')).decode('utf-8')

    def encrypt_media(self):
        """Encrypt the media file content."""
        if self.media and not self.media_encrypted:
            cipher = Fernet(settings.ENCRYPTION_KEY.encode())
            with self.media.open('rb') as f:
                media_content = f.read()
            encrypted_content = cipher.encrypt(media_content)
            # Save encrypted content back to the file
            self.media.save(self.media.name, ContentFile(encrypted_content), save=False)
            self.media_encrypted = True

    def decrypt_media(self):
        if self.media and self.media_encrypted:
            cipher = Fernet(settings.ENCRYPTION_KEY.encode())
            try:
                with self.media.open('rb') as f:
                    encrypted_content = f.read()
                decrypted_content = cipher.decrypt(encrypted_content)
                return decrypted_content
            except Exception as e:
                print(f"Decryption error: {e}")
                return None
        return None


    def sign_message(self):
        """Sign the encrypted message."""
        private_key = self.sender.get_private_key()
        message_data = (self.text_encrypted or "").encode('utf-8')
        signature = private_key.sign(
            message_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        self.signature = signature.hex()

    def verify_signature(self):
        """Verify the signature."""
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


    def save(self, *args, **kwargs):
        if self.text_encrypted and not self.text_encrypted.startswith("gAAAA"):
            self.text_encrypted = self.encrypt_message(self.text_encrypted)
        if self.media and not self.media_encrypted:
            super().save(*args, **kwargs)  # Save first to get an ID
            self.encrypt_media()
            super().save(*args, **kwargs)  # Save again with encrypted media
        else:
            super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.sender.email} -> {self.receiver.email}: [Encrypted]"

# In users/models.py
class GroupCreationRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="group_creation_requests")
    requested_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(null=True, default=None)  # None = pending, True = approved, False = rejected
    reviewed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Request by {self.user.email} at {self.requested_at}"



# In models.py
class Group(models.Model):
    name = models.CharField(max_length=100, unique=True)
    creator = models.ForeignKey(CustomUser, related_name="created_groups", on_delete=models.CASCADE)
    members = models.ManyToManyField(CustomUser, related_name="group_memberships")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class GroupMessage(models.Model):
    group = models.ForeignKey(Group, related_name="messages", on_delete=models.CASCADE)
    sender = models.ForeignKey(CustomUser, related_name="group_sent_messages", on_delete=models.CASCADE)
    text_encrypted = models.TextField(blank=True, null=True)
    media = models.FileField(upload_to=message_media_upload_path, blank=True, null=True)
    media_encrypted = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)
    signature = models.TextField(blank=True, null=True)  # Store signature

    def encrypt_message(self, text):
        cipher = Fernet(settings.ENCRYPTION_KEY.encode())
        return cipher.encrypt(text.encode('utf-8')).decode('utf-8')

    def decrypt_message(self):
        if not self.text_encrypted:
            return ""
        cipher = Fernet(settings.ENCRYPTION_KEY.encode())
        return cipher.decrypt(self.text_encrypted.encode('utf-8')).decode('utf-8')

    def encrypt_media(self):
        """Encrypt the media file content."""
        if self.media and not self.media_encrypted:
            cipher = Fernet(settings.ENCRYPTION_KEY.encode())
            with self.media.open('rb') as f:
                media_content = f.read()
            encrypted_content = cipher.encrypt(media_content)
            self.media.save(self.media.name, ContentFile(encrypted_content), save=False)
            self.media_encrypted = True

    def decrypt_media(self):
        if self.media and self.media_encrypted:
            cipher = Fernet(settings.ENCRYPTION_KEY.encode())
            try:
                with self.media.open('rb') as f:
                    encrypted_content = f.read()
                decrypted_content = cipher.decrypt(encrypted_content)
                return decrypted_content
            except Exception as e:
                print(f"Decryption error: {e}")
                return None
        return None

    def sign_message(self):
        """Sign the encrypted message."""
        private_key = self.sender.get_private_key()
        message_data = (self.text_encrypted or "").encode('utf-8')
        signature = private_key.sign(
            message_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        self.signature = signature.hex()

    def verify_signature(self):
        """Verify the signature."""
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

    def save(self, *args, **kwargs):
        if self.text_encrypted and not self.text_encrypted.startswith("gAAAA"):
            self.text_encrypted = self.encrypt_message(self.text_encrypted)
        if self.media and not self.media_encrypted:
            super().save(*args, **kwargs)  # Save first to get an ID
            self.encrypt_media()
            super().save(*args, **kwargs)  # Save again with encrypted media
        else:
            super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.sender.email} in {self.group.name}: [Encrypted]"


class AccountDeactivationRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="deactivation_requests")
    requested_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(null=True, default=None)  # None = pending, True = approved, False = rejected
    reviewed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Deactivation request by {self.user.email} at {self.requested_at}"

class AccountDeletionRequest(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="deletion_requests")
    requested_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(null=True, default=None)  # None = pending, True = approved, False = rejected
    reviewed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Deletion request by {self.user.email} at {self.requested_at}"



class Report(models.Model):
    reporter = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="reports_made")
    message = models.ForeignKey(Message, on_delete=models.CASCADE, null=True, blank=True)
    group_message = models.ForeignKey(GroupMessage, on_delete=models.CASCADE, null=True, blank=True)
    reason = models.TextField()
    reported_at = models.DateTimeField(auto_now_add=True)
    reviewed = models.BooleanField(default=False)
    action_taken = models.CharField(max_length=100, blank=True, null=True)

    def __str__(self):
        return f"Report by {self.reporter.email} on {self.message or self.group_message}"

class Block(models.Model):
    blocker = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="blocks")
    blocked_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="blocked_by")
    blocked_at = models.DateTimeField(auto_now_add=True)


    class Meta:
        unique_together = ('blocker', 'blocked_user')

    def __str__(self):
        return f"{self.blocker.email} blocked {self.blocked_user.email}"


class ReportRequest(models.Model):
    reporter = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="report_requests")
    message = models.ForeignKey(Message, on_delete=models.CASCADE, null=True, blank=True)
    group_message = models.ForeignKey(GroupMessage, on_delete=models.CASCADE, null=True, blank=True)
    reported_message_id = models.IntegerField()  # Renamed from message_id
    reason = models.TextField()
    is_group = models.BooleanField(default=False)
    requested_at = models.DateTimeField(auto_now_add=True)
    approved = models.BooleanField(null=True, default=None)  # None = pending, True = approved, False = rejected
    reviewed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Report request by {self.reporter.email} for message {self.reported_message_id}"


class Product(models.Model):
    seller = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="products")
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    is_sold = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    image = models.ImageField(upload_to='product_images/', blank=True, null=True, validators=[FileExtensionValidator(['png', 'jpg', 'jpeg'])])

    def __str__(self):
        return self.title

class Wallet(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name="wallet")
    balance = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)

    def __str__(self):
        return f"{self.user.email}'s Wallet: ${self.balance}"

class Transaction(models.Model):
    sender = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sent_transactions')
    receiver = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='received_transactions')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    product = models.ForeignKey('Product', on_delete=models.SET_NULL, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    is_topup = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.sender.email} -> {self.receiver.email} (${self.amount})"