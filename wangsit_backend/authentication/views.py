from django.shortcuts import render

# Create your views here.

def index(request):
    """
    Render the OAuth test page
    """
    return render(request, 'authentication/index.html')

def profile_test(request):
    """
    Render the profile update test page
    """
    return render(request, 'authentication/profile_test.html')
