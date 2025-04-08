from django.contrib import admin
from django.utils import timezone
from django.db.models import F
from .models import (CustomUser, Message, Group, GroupMessage, GroupCreationRequest,
                    AccountDeactivationRequest, AccountDeletionRequest, Report,
                    Block, Product, Wallet, Transaction)

# Message Admin
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'timestamp', 'preview_message')

    def preview_message(self, obj):
        return "[Encrypted Message]"
    preview_message.short_description = "Message Preview"

# GroupCreationRequest Admin
class GroupCreationRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'requested_at', 'approved', 'reviewed_at')
    list_filter = ('approved',)
    actions = ['approve_requests']

    def save_model(self, request, obj, form, change):
        if obj.approved and not obj.user.is_verified_by_admin:
            print(f"Approving request for {obj.user.email}, setting is_verified_by_admin to True")
            obj.user.is_verified_by_admin = True
            obj.user.save()
            if not obj.reviewed_at:
                obj.reviewed_at = timezone.now()
        elif not obj.approved and obj.user.is_verified_by_admin:
            print(f"Revoking approval for {obj.user.email}, setting is_verified_by_admin to False")
            obj.user.is_verified_by_admin = False
            obj.user.save()
        super().save_model(request, obj, form, change)

    def approve_requests(self, request, queryset):
        for req in queryset:
            if not req.approved:
                req.approved = True
                req.reviewed_at = timezone.now()
                req.user.is_verified_by_admin = True
                req.user.save()
                req.save()
        self.message_user(request, "Selected requests have been approved and users verified.")
    approve_requests.short_description = "Approve selected group creation requests"

# AccountDeactivationRequest Admin
class AccountDeactivationRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'requested_at', 'approved', 'reviewed_at')
    list_filter = ('approved',)
    actions = ['approve_requests', 'reject_requests']

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if obj.approved and obj.approved != form.initial.get('approved'):
            print(f"Deactivating account for {obj.user.email}")
            obj.user.is_active = False
            obj.user.save()
            if not obj.reviewed_at:
                obj.reviewed_at = timezone.now()
        elif obj.approved is False and obj.approved != form.initial.get('approved'):
            if not obj.reviewed_at:
                obj.reviewed_at = timezone.now()

    def approve_requests(self, request, queryset):
        for req in queryset:
            if not req.approved:
                req.approved = True
                req.reviewed_at = timezone.now()
                req.user.is_active = False
                req.user.save()
                req.save()
        self.message_user(request, "Selected deactivation requests have been approved.")
    approve_requests.short_description = "Approve selected deactivation requests"

    def reject_requests(self, request, queryset):
        for req in queryset:
            if req.approved is None:
                req.approved = False
                req.reviewed_at = timezone.now()
                req.save()
        self.message_user(request, "Selected deactivation requests have been rejected.")
    reject_requests.short_description = "Reject selected deactivation requests"

# AccountDeletionRequest Admin
class AccountDeletionRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'requested_at', 'approved', 'reviewed_at')
    list_filter = ('approved',)
    actions = ['approve_requests', 'reject_requests']

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        if obj.approved and obj.approved != form.initial.get('approved'):
            print(f"Deleting account for {obj.user.email}")
            Message.objects.filter(sender=obj.user).delete()
            Message.objects.filter(receiver=obj.user).delete()
            GroupMessage.objects.filter(sender=obj.user).delete()
            Group.objects.filter(creator=obj.user).delete()
            obj.user.delete()
            if not obj.reviewed_at:
                obj.reviewed_at = timezone.now()
        elif obj.approved is False and obj.approved != form.initial.get('approved'):
            if not obj.reviewed_at:
                obj.reviewed_at = timezone.now()

    def approve_requests(self, request, queryset):
        for req in queryset:
            if not req.approved:
                req.approved = True
                req.reviewed_at = timezone.now()
                req.save()
                Message.objects.filter(sender=req.user).delete()
                Message.objects.filter(receiver=req.user).delete()
                GroupMessage.objects.filter(sender=req.user).delete()
                Group.objects.filter(creator=req.user).delete()
                req.user.delete()
        self.message_user(request, "Selected deletion requests have been approved and accounts deleted.")
    approve_requests.short_description = "Approve selected deletion requests"

    def reject_requests(self, request, queryset):
        for req in queryset:
            if req.approved is None:
                req.approved = False
                req.reviewed_at = timezone.now()
                req.save()
        self.message_user(request, "Selected deletion requests have been rejected.")
    reject_requests.short_description = "Reject selected deletion requests"

# Report Admin
class ReportAdmin(admin.ModelAdmin):
    list_display = ('reporter', 'message_content', 'reason', 'reported_at', 'reviewed', 'action_taken', 'actions_column')
    list_filter = ('reviewed', 'action_taken', 'reported_at')
    search_fields = ('reporter__email', 'reason', 'message__text_encrypted', 'group_message__text_encrypted')
    actions = ['ban_user', 'delete_message', 'dismiss_report']

    def message_content(self, obj):
        if obj.message:
            return obj.message.decrypt_message()[:50] or "[Media Only]"
        elif obj.group_message:
            return obj.group_message.decrypt_message()[:50] or "[Media Only]"
        return "N/A"
    message_content.short_description = "Message"

    def actions_column(self, obj):
        if not obj.reviewed:
            from django.urls import reverse
            from django.utils.html import format_html
            return format_html(
                '<a href="{}" class="button">Ban User</a> '
                '<a href="{}" class="button">Delete Message</a> '
                '<a href="{}" class="button">Dismiss</a>',
                reverse('admin:ban_user', args=[obj.id]),
                reverse('admin:delete_message', args=[obj.id]),
                reverse('admin:dismiss_report', args=[obj.id]),
            )
        return "Reviewed"
    actions_column.short_description = "Actions"

    def ban_user(self, request, queryset):
        for report in queryset:
            if not report.reviewed:
                user_to_ban = report.message.sender if report.message else report.group_message.sender
                user_to_ban.is_active = False
                user_to_ban.save()
                Group.objects.filter(members=user_to_ban).update(members=F('members').remove(user_to_ban))
                report.action_taken = "User banned"
                report.reviewed = True
                report.save()
        self.message_user(request, "Selected users have been banned.")
    ban_user.short_description = "Ban selected users"

    def delete_message(self, request, queryset):
        for report in queryset:
            if not report.reviewed:
                if report.message:
                    report.message.delete()
                elif report.group_message:
                    report.group_message.delete()
                report.action_taken = "Message deleted"
                report.reviewed = True
                report.save()
        self.message_user(request, "Selected messages have been deleted.")
    delete_message.short_description = "Delete selected messages"

    def dismiss_report(self, request, queryset):
        for report in queryset:
            if not report.reviewed:
                report.action_taken = "Dismissed"
                report.reviewed = True
                report.save()
        self.message_user(request, "Selected reports have been dismissed.")
    dismiss_report.short_description = "Dismiss selected reports"

# Block Admin
class BlockAdmin(admin.ModelAdmin):
    list_display = ('blocker', 'blocked_user', 'blocked_at')
    list_filter = ('blocked_at',)
    search_fields = ('blocker__email', 'blocked_user__email')

# CustomUser Admin
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('email', 'full_name', 'mobile', 'is_active', 'is_verified_by_admin', 'is_admin')
    list_filter = ('is_active', 'is_verified_by_admin', 'is_admin')
    search_fields = ('email', 'full_name', 'mobile')
    actions = ['activate_users', 'deactivate_users']

    def activate_users(self, request, queryset):
        queryset.update(is_active=True)
    activate_users.short_description = "Activate selected users"

    def deactivate_users(self, request, queryset):
        queryset.update(is_active=False)
    deactivate_users.short_description = "Deactivate selected users"

# Product Admin
class ProductAdmin(admin.ModelAdmin):
    list_display = ('title', 'seller', 'price', 'is_sold', 'created_at')
    list_filter = ('is_sold',)
    search_fields = ('title', 'seller__email', 'description')
    actions = ['mark_as_sold', 'mark_as_available']

    def mark_as_sold(self, request, queryset):
        queryset.update(is_sold=True)
    mark_as_sold.short_description = "Mark selected products as sold"

    def mark_as_available(self, request, queryset):
        queryset.update(is_sold=False)
    mark_as_available.short_description = "Mark selected products as available"

# Wallet Admin
class WalletAdmin(admin.ModelAdmin):
    list_display = ('user', 'balance')
    search_fields = ('user__email',)
    actions = ['reset_balance']

    def reset_balance(self, request, queryset):
        queryset.update(balance=0.00)
    reset_balance.short_description = "Reset balance to $0.00"

# Transaction Admin
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('sender', 'receiver', 'amount', 'product', 'timestamp', 'is_topup')
    list_filter = ('is_topup',)
    search_fields = ('sender__email', 'receiver__email', 'product__title')

# Register Models with their Admin Classes
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Message, MessageAdmin)
admin.site.register(Group)
admin.site.register(GroupMessage)
admin.site.register(GroupCreationRequest, GroupCreationRequestAdmin)
admin.site.register(AccountDeactivationRequest, AccountDeactivationRequestAdmin)
admin.site.register(AccountDeletionRequest, AccountDeletionRequestAdmin)
admin.site.register(Report, ReportAdmin)
admin.site.register(Block, BlockAdmin)
admin.site.register(Product, ProductAdmin)
admin.site.register(Wallet, WalletAdmin)
admin.site.register(Transaction, TransactionAdmin)