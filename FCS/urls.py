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

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)