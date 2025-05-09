from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import *

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    role = serializers.ChoiceField(choices=User.ROLE_CHOICES)

    class Meta:
        model = User
        fields = ['username', 'email', 'password','role']

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        user.is_active = False  # Set the user to inactive until email is verified
        user.save()
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()



class FileUploadSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()

    class Meta:
        model = FileUpload
        fields = ['id','file', 'file_url']
        
    def get_file_url(self, obj):
        return obj.file.url

    def validate_file(self, value):
        allowed_extensions = ['.pptx', '.docx', '.xlsx']
        import os
        ext = os.path.splitext(value.name)[1]
        if ext.lower() not in allowed_extensions:
            raise serializers.ValidationError('Only .pptx, .docx, and .xlsx files are allowed.')
        return value