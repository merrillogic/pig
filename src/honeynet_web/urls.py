from django.conf.urls.defaults import patterns, include, url
from django.contrib import admin
from tastypie.api import Api
from honeywall.api import AnalysisResource, AttackResource, PacketResource, ClassifyResource

admin.autodiscover()

v1_api = Api(api_name='v1')
v1_api.register(AttackResource())
v1_api.register(PacketResource())
v1_api.register(ClassifyResource())

urlpatterns = patterns('',
    # Examples:
    #url(r'^$', 'honeywall.views.dashboard'),
    url(r'^$', 'honeywall.views.index'),
    url(r'^attack/(?P<attack_id>\d+)$', 'honeywall.views.attack'),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),

    # API!
    (r'^api/', include(v1_api.urls)),
    url(r'^api/v1/traffic_analysis', 'honeywall.views.traffic_analysis'),
)
