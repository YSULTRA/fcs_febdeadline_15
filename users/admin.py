from django.contrib import admin
from .models import CustomUser,Message

admin.site.register(CustomUser)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'timestamp', 'preview_message')

    def preview_message(self, obj):
        return "[Encrypted Message]"
    preview_message.short_description = "Message Preview"

admin.site.register(Message, MessageAdmin)