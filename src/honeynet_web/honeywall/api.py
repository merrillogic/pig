#import base64
from django.core.urlresolvers import reverse
from tastypie import fields
from tastypie.resources import ModelResource, ALL, ALL_WITH_RELATIONS
from honeywall.models import Packet, Attack

class AttackResource(ModelResource):

    def dehydrate(self, bundle):
        url = reverse('api_dispatch_list', kwargs={'resource_name': 'packet',
                                                   'api_name': 'v1',
                                                   })
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
        #includes = []
        #filtering = {
        #}


class PacketResource(ModelResource):
    attacks = fields.ToManyField('honeywall.api.AttackResource', 'attacks', 'packet')

    class Meta:
        queryset = Packet.objects.all()
        resource_name = 'packet'
        filtering = {
            'attacks': ALL_WITH_RELATIONS,
        }
        allowed_methods=['get']

    def build_filters(self, filters=None):
        if filters is None:
            filters = {}
        print filters

        orm_filters = super(PacketResource, self).build_filters(filters)

        if 'attack' in filters:
            a = int(filters['attack'])
            orm_filters={'attacks__in': [a]}

        return orm_filters

