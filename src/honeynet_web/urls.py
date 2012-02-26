from django.conf.urls.defaults import patterns, include, url
from tastypie.api import Api
from honeywall.api import AttackResource, PacketResource, ClassifyResource, TrafficResource

v1_api = Api(api_name='v1')
v1_api.register(AttackResource())
v1_api.register(PacketResource())
v1_api.register(ClassifyResource())
v1_api.register(TrafficResource())

urlpatterns = patterns('',
    # Examples:
    #url(r'^$', 'honeywall.views.dashboard'),
    url(r'^$', 'honeywall.views.index'),
    url(r'^attack/(?P<attack_id>\d+)$', 'honeywall.views.attack'),

    # API!
    (r'^api/', include(v1_api.urls)),
    url(r'^api/v1/traffic_analysis', 'honeywall.views.traffic_analysis'),
)
