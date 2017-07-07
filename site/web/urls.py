from django.conf.urls import url

from web.views import *

urlpatterns = [
	url(r'^$', index, name='index'),
    url(r'^join$', join, name='join'),
    url(r'^faq$', faq, name='faq'),
]
