"""
URL configuration for FCS project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.urls import include
from django.conf import settings
from django.conf.urls.static import static
from users.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    path("api/users/", include("users.urls")),  # Ensure this matches BASE_URL in script.js
    path('', home, name='home'),
    path('login/', UserLoginView.as_view(), name='login'),  # Add this line
    path('logout/', UserLogoutView.as_view(), name='logout'),
    path("profile/", profile_view, name="user-profile"),
    path("profile/data/", get_user_profile, name="profile-data"),  # Fix URL pattern for profile update
    path('search-users/', search_users, name='search-users'),
    path("users/", include("users.urls")),
    path("users/get-current-user/", get_current_user, name="get_current_user"),
    path("search-users/", search_users, name="search_users"),

    path("api/chat/messages/", get_messages, name="get_messages"),
    path("api/chat/send-message/", send_message, name="send_message"),
    path('api/chat/messages/<str:email>/', get_messages, name='get_messages'),  # Add this line
    path("search-users/", search_users, name="search_users"),
    path("chat/", chat_view, name="chat_view"),
    path("send-message/", send_message, name="send_message"),
    path("get-messages/", get_messages, name="get_messages"),
    path("serve-media/<int:message_id>/", serve_media, name="serve-media"),
    path('get-user-profile/', get_user_profile, name='get_user_profile'),

    path("password-reset-request/", PasswordResetRequestView.as_view(), name="password_reset_request"),
    path("password-reset-confirm/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path('create-group/', create_group, name='create_group'),
    path('send-group-message/', send_group_message, name='send_group_message'),
    path('get-group-messages/', get_group_messages, name='get_group_messages'),
    path('serve-group-media/<int:message_id>/', serve_group_media, name='serve_group_media'),
    path('group-chat/', group_chat_view, name='group_chat_view'),
    path('manage-group-requests/', manage_group_requests, name='manage_group_requests'),


    path("request-deactivation/", request_account_deactivation, name="request_deactivation"),
    path("confirm-deactivation/", confirm_account_deactivation, name="confirm_deactivation"),
    path("request-deletion/", request_account_deletion, name="request_deletion"),
    path("confirm-deletion/", confirm_account_deletion, name="confirm_deletion"),


    path('report-message/', report_message, name='report_message'),
    path("confirm-report/", confirm_report, name="confirm_report"),
    path('block-user/', block_user, name='block_user'),
    path('admin-reports/', admin_reports, name='admin_reports'),
    path('review-report/<int:report_id>/', review_report, name='review_report'),

    path('admin/ban-user/<int:report_id>/', ban_user, name='ban_user'),
    path('admin/delete-message/<int:report_id>/', delete_message, name='delete_message'),
    path('admin/dismiss-report/<int:report_id>/', dismiss_report, name='dismiss_report'),


    path("list-product/", list_product, name="list_product"),
    path("get-products/", get_products, name="get_products"),
    path("buy-product/", buy_product, name="buy_product"),
    path("topup-wallet/", topup_wallet, name="topup_wallet"),
    path("wallet-balance/", get_wallet_balance, name="get_wallet_balance"),
    path("report-message/", report_message, name="report_message"),
    path("confirm-report/", confirm_report, name="confirm_report"),
    path("marketplace/", marketplace_view, name="marketplace"),
    path("get-your-products/", get_your_products, name="get_your_products"),  # New endpoint

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)