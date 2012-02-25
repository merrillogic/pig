from django.core.urlresolvers import reverse
from tastypie.authorization import Authorization
from tastypie import fields
from tastypie.resources import ModelResource, ALL, ALL_WITH_RELATIONS
from honeywall.models import Packet, Attack
from honeywall.utils import protocol_lookup

class ClassifyResource(ModelResource):
    class Meta:
        authorization = Authorization()
        queryset = Attack.objects.all()
        resource_name = 'classify'
        fields = ['false_positive', 'id']
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get', 'put']


class AttackResource(ModelResource):
    threat_level = fields.CharField(attribute='threat_level')

    def dehydrate(self, bundle):
        url = reverse('api_dispatch_list', kwargs={'resource_name': 'packet', 'api_name': 'v1',})
        if '?' in url:
            url += '&'
        else:
            url += '?'
        url += 'attack=' + bundle.data['id']

        bundle.data['packets'] = url

        return bundle

    class Meta:
        queryset = Attack.objects.all()
        resource_name = 'attack'
        allowed_methods=['get']
        filtering = {
                'attack_type': ALL,
                'classification_time': ALL,
                'destination_ip': ALL,
                'end_time': ALL,
                'false_positive': ALL,
                'score': ALL,
                'source_ip': ALL,
                'start_time': ALL,
        }


class PacketResource(ModelResource):
    attacks = fields.ToManyField('honeywall.api.AttackResource', 'attacks', 'packet')

    def dehydrate(self, bundle):
        if bundle.data['protocol']:
            bundle.data['protocol'] = protocol_lookup(bundle.data['protocol'])

        return bundle

    class Meta:
        queryset = Packet.objects.all()
        resource_name = 'packet'
        filtering = {
            'attacks': ALL_WITH_RELATIONS,
            'classification_time': ALL,
            'dest_port': ALL,
            'destination_ip': ALL,
            'destination_mac': ALL,
            'protocol': ALL,
            'resource_uri': ALL,
            'source_ip': ALL,
            'source_mac': ALL,
            'source_port': ALL,
            'time': ALL,
        }
        allowed_methods=['get']

    def build_filters(self, filters=None):
        if filters is None:
            filters = {}

        orm_filters = super(PacketResource, self).build_filters(filters)

        if 'attack' in filters:
            a = int(filters['attack'])
            orm_filters={'attacks__in': [a]}

        return orm_filters

