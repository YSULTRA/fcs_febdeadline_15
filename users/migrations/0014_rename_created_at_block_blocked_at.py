# Generated by Django 5.1.7 on 2025-04-08 13:50

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_report_block'),
    ]

    operations = [
        migrations.RenameField(
            model_name='block',
            old_name='created_at',
            new_name='blocked_at',
        ),
    ]
