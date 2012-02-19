from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from tastypie.api import Api
from honeywall.api import AttackResource, PacketResource

admin.autodiscover()

v1_api = Api(api_name='v1')
v1_api.register(AttackResource())
v1_api.register(PacketResource())

urlpatterns = patterns('',
    # Examples:
    #url(r'^$', 'honeywall.views.dashboard'),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),

    # API!
    (r'^api/', include(v1_api.urls)),
)
