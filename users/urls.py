from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.user_login, name='login'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('home/', views.home, name='home'),
]
