from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import AbstractUser, PermissionsMixin, UserManager
from django.db import models


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(verbose_name='유저네임', max_length=16, unique=True)
    email = models.EmailField(verbose_name='이메일', blank=True)
    password = models.CharField(verbose_name='비밀번호', max_length=128)
    is_staff = models.BooleanField(verbose_name='스태프 권한', default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'

    class Meta:
        verbose_name = '유저'
        verbose_name_plural = verbose_name
