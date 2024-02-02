from django.shortcuts import render
from django.http import JsonResponse, HttpResponse

def base_view(request):
    data = {'message': 'Welcome to the base app API!'}
    return HttpResponse("<h1>Home</h1><br><a href='api/'>Api</a>")
