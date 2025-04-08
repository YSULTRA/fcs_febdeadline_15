from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static

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
    path("serve-media/<int:message_id>/", serve_media, name="serve-media"),
    path("password-reset-request/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),

    path("request-deactivation/", request_account_deactivation, name="request_deactivation"),
    path("confirm-deactivation/", confirm_account_deactivation, name="confirm_deactivation"),
    path("request-deletion/", request_account_deletion, name="request_deletion"),
    path("confirm-deletion/", confirm_account_deletion, name="confirm_deletion"),


    path('report-message/', report_message, name='report_message'),
    path('block-user/', block_user, name='block_user'),
    path('admin-reports/', admin_reports, name='admin_reports'),
    path('review-report/<int:report_id>/', review_report, name='review_report'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
