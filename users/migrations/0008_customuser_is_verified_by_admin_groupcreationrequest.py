# Generated by Django 5.1.7 on 2025-03-31 16:33

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0007_group_groupmessage'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='is_verified_by_admin',
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name='GroupCreationRequest',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('requested_at', models.DateTimeField(auto_now_add=True)),
                ('approved', models.BooleanField(default=None, null=True)),
                ('reviewed_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='group_creation_requests', to='users.customuser')),
            ],
        ),
    ]
