from django.conf.urls.defaults import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    url(r'^$', 'honeywall.views.dashboard'),
    url(r'^api/attack/(?P<attack_id>\d+)/$', 'honeywall.api.attack'),
    url(r'^api/attack/(?P<attack_id>\d+)/packets/$', 'honeywall.api.attack_packets'),
    url(r'^api/attacks/$', 'honeywall.api.attacks'),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
)
