from django.shortcuts import render

def index(request):
    return render(request, 'web/index.html')

def join(request):
    return render(request, 'web/join.html')

def faq(request):
    return render(request, 'web/faq.html')

def writeup(request):
    return render(request, 'web/writeup.html')
