from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ValidationError

import settings

User = get_user_model()


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        errors = dict()
        if not User.objects.filter(username=username).exists():
            errors['password'] = '존재하지 않는 유저입니다.'
        else:
            user = User.objects.get(username=username)
            if not check_password(password, user.password):
                errors['password'] = '비밀번호가 틀립니다.'
                raise ValidationError({'password': '비밀번호가 틀립니다.'})
        if errors:
            raise ValidationError(errors)

        return attrs

    def create(self, validated_data):
        user = authenticate(**validated_data)
        Token.objects.get_or_create(user=user)

        return user


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.EmailField()
    password1 = serializers.CharField()
    password2 = serializers.CharField()

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        errors = dict()
        if User.objects.filter(username=username).exists():
            errors['username'] = '이미 존재하는 유저입니다.'
        if password1 != password2:
            msg = '비밀번호가 일치하지 않습니다.'
            errors['password1'] = msg
            errors['password2'] = msg
        if errors:
            raise ValidationError(errors)

        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        Token.objects.get_or_create(user=user)

        return user


class ProfileSerializer(serializers.Serializer):
    username = serializers.CharField(read_only=True)
    email = serializers.EmailField()
    password1 = serializers.CharField(write_only=True, allow_blank=True)
    password2 = serializers.CharField(write_only=True, allow_blank=True)

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        errors = dict()
        if username != self.instance.username and User.objects.filter(username=username).exists():
            errors['username'] = '이미 존재하는 유저입니다.'
        if password1 != password2:
            msg = '비밀번호가 일치하지 않습니다.'
            errors['password1'] = msg
            errors['password2'] = msg
        if errors:
            raise ValidationError(errors)

        return attrs

    def update(self, instance, validated_data):
        email = validated_data.get('email')
        password = validated_data.get('password1')
        instance.email = email
        if password:
            password = make_password(password)
            instance.password = password
        instance.save()

        return instance


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True)

    def validate(self, attrs):
        email = attrs.get('email')

        errors = dict()
        if not User.objects.filter(email=email).exists():
            errors['email'] = '가입된 이메일이 없습니다.'
        if errors:
            raise ValidationError(errors)

        return attrs

    def send_email(self, user):
        request = self.context.get('request')
        current_site = get_current_site(request)
        subject = f'{current_site.name} 비밀번호 재설정'
        context = {
            'domain': current_site.domain,
            'site_name': current_site.name,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': default_token_generator.make_token(user),
            'protocol': 'https' if request.is_secure() else 'http',
        }
        html_email = loader.render_to_string('account/password_reset_email.html', context)
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL')
        to = [user.email]

        email_message = EmailMultiAlternatives(
            subject=subject,
            from_email=from_email,
            to=to,
            alternatives=[(html_email, 'text/html')]
        )
        email_message.send()

    def create(self, validated_data):
        user = User.objects.get(**validated_data)
        self.send_email(user)

        return user


class PasswordResetConfirmSerializer(serializers.Serializer):
    password1 = serializers.CharField(write_only=True, allow_blank=True)
    password2 = serializers.CharField(write_only=True, allow_blank=True)
    uid = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')
        uid = attrs.get('uid')
        token = attrs.get('token')

        try:
            uid = force_text(urlsafe_base64_decode(uid))
            self.user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise ValidationError({'uid': '이미 비밀번호를 변경하셨습니다.'})

        if not default_token_generator.check_token(self.user, token):
            raise ValidationError({'token': '이미 비밀번호를 변경하셨습니다.'})

        errors = dict()
        if password1 != password2:
            msg = '비밀번호가 일치하지 않습니다.'
            errors['password1'] = msg
            errors['password2'] = msg
        if errors:
            raise ValidationError(errors)

        return attrs

    def create(self, validated_data):
        password = validated_data.get('password1')
        self.user.set_password(password)
        self.user.save()

        return self.user
