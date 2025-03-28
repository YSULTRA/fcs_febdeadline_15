from django import forms
from users.models import CustomUser

class ProfileUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'bio', 'profile_picture']

    def __init__(self, *args, **kwargs):
        request = kwargs.pop('request', None)  # Retrieve request from kwargs
        super().__init__(*args, **kwargs)

        if request and "user_id" in request.session:
            user_id = request.session["user_id"]
            try:
                user = CustomUser.objects.get(id=user_id)
                self.instance = user  # Set instance to the logged-in user
            except CustomUser.DoesNotExist:
                pass  # Handle invalid session user case
