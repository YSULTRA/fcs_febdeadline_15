from rest_framework import serializers
from .models import CustomUser

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    full_name = serializers.CharField(required=True)  # Ensure full_name is required

    class Meta:
        model = CustomUser
        fields = ["email", "mobile", "full_name", "password"]

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data["email"],
            mobile=validated_data["mobile"],
            password=validated_data["password"],
            full_name=validated_data["full_name"],  # Ensure full_name is passed
        )
        user.email_otp = user.generate_otp()
        user.mobile_otp = user.generate_otp()
        user.save()
        return user


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["username", "full_name", "bio", "profile_picture"]
        extra_kwargs = {
            "username": {"required": True},
            "full_name": {"required": True},
        }


