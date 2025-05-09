
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.conf import settings
from django.utils.crypto import get_random_string

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('ops', 'Operations'),
        ('client', 'Client'),
    )
    is_verified = models.BooleanField(default=False)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='client')

def user_directory_path(instance, filename):
    # File will be uploaded to MEDIA_ROOT/user_<id>/<filename>
    return f'user_{instance.uploaded_by.id}/{filename}'

class FileUpload(models.Model):
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    file = models.FileField(upload_to=user_directory_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    download_token = models.CharField(max_length=255, blank=True, null=True)
    
    def __str__(self):
        return self.file.name
    
    def generate_download_token(self):
        """
        Generate a random token for secure file download.
        """
        self.download_token = get_random_string(length=32)  # Generate random 32-character token
        self.save()