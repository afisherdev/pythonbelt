# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect, HttpResponse

def index(request):
    
    return render(request, 'python_belt/index.html')
def login(request):
    return redirect('/')

def register(request):
    return redirect('/')