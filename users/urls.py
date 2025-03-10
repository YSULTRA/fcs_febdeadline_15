from django.urls import path
from .views import (
    UserRegistrationView, VerifyOTPView, UserLoginView, UserProfileView,profile_view,get_user_profile
)

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("profile/<str:email>/", UserProfileView.as_view(), name="user-profile"),
    path("profile/data/", get_user_profile, name="profile-data"),
]
