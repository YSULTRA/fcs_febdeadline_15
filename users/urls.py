from django.urls import path
from .views import *

urlpatterns = [
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("verify-otp/", VerifyOTPView.as_view(), name="verify-otp"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("profile/<str:email>/", UserProfileView.as_view(), name="user-profile"),
    path("profile/data/", get_user_profile, name="profile-data"),
    path("get-user-by-username/", get_user_by_username, name="get_user_by_username"),
    path("send/", send_message, name="send-message"),
    path("get/<str:email>/", get_messages, name="get-messages"),
    path("search-users/", search_users, name="search-users"),
    path("", chat_view, name="chat-ui"),
    path("api/chat/messages/", get_messages, name="get_messages"),
    path("api/chat/send-message/", send_message, name="send_message"),
    path('api/chat/messages/<str:email>/', get_messages, name='get_messages'),
    path("send-message/", send_message, name="send_message"),
    path("get-messages/", get_messages, name="get_messages"),  # Add this line
    path("search-users/", search_users, name="search_users"),

]
