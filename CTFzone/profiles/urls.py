from django.urls import path 
from . import views


urlpatterns = [
    
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('confirm_email/<str:token>/<str:email>/', views.confirm_email, name='confirm_email'),  # Email confirmation URL
    
    
]