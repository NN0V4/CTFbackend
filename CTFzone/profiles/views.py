import uuid
from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from .forms import UniversityLoginForm, UniversitySignUpForm
from django.contrib.auth.models import User
from django.contrib import messages  
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone
from django.urls import reverse


def signup_view(request):
    form = UniversitySignUpForm(request.POST or None)
    
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']

        if User.objects.filter(username=email).exists():
            # User already registered case
            messages.error(request, "This email is already registered.")
        else:
            # Create and save the user if not registered
            user = User.objects.create_user(username=email, email=email, password=password)
            user.is_active = True  # Directly set user as active
            user.save()


            token = str(uuid.uuid4())
            user.profile.verification_token = token
            user.profile.verification_sent_at = timezone.now()
            user.profile.save() 

            # Prepare email content using `email.html`
            confirmation_link = request.build_absolute_uri(reverse('confirm_email', args=[token, email]))
            email_content = render_to_string('profiles/email.html', {'confirmation_link': confirmation_link}) 


            send_mail(
            subject='Email Confirmation',
            message='',
            from_email='ctfzone99@gmail.com',
            recipient_list=[email],
            html_message=email_content ) # Use `email.html` for the email template
            
            messages.success(request, 'Verification email sent! Please check your inbox.')
            return redirect('signup')  # Redirect to login after successful signup

    return render(request, 'profiles/signup.html', {'form': form})







def confirm_email(request, token, email):
    try:
        user = User.objects.get(email=email)
        if user.profile.verification_token == token:
            user.is_active = True
            user.save()
            user.profile.verification_token = None
            user.profile.save()
            messages.success(request, 'Your email has been confirmed.')
            return redirect('signup')
        else:
            messages.error(request, 'Invalid confirmation link.')
    except User.DoesNotExist:
        messages.error(request, 'Invalid confirmation link.')
    return redirect('signup')






def login_view(request):
    form = UniversityLoginForm(request.POST or None)
    
    if request.method == 'POST' and form.is_valid():
        email = form.cleaned_data['email']
        password = form.cleaned_data['password']
        
        try:
            user = User.objects.get(email=email)
            user_auth = authenticate(request, username=user.username, password=password)
            
            if user_auth is not None:
                # Successful login
                login(request, user_auth)
                return redirect('home')  # Redirect to the homepage after successful login
            else:
                # Invalid password case
                messages.error(request, "Invalid email or password.")
        
        except User.DoesNotExist:
            # User does not exist case
            messages.error(request, "No account with this email exists.")
    
    # Keep the user on the login page if there’s an error
    return render(request, 'profiles/login.html', {'form': form})




