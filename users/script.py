def update_existing_group_messages():
    from users.models import GroupMessage
    messages = GroupMessage.objects.all()
    for msg in messages:
        if msg.text_encrypted and all(c in '0123456789abcdefABCDEF' for c in msg.text_encrypted):
            # Assume hex-encoded text is encrypted
            msg.is_encrypted = True
            msg.save()
        else:
            msg.is_encrypted = False  # Plain text
            msg.save()
    print("Updated existing group messages")