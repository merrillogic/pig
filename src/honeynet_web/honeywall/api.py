import base64
from tastypie import fields
from tastypie.resources import ModelResource, ALL, ALL_WITH_RELATIONS
from honeywall.models import Packet, Attack

class AttackResource(ModelResource):
    packets = fields.ManyToManyField('honeywall.api.PacketResource', 'packet_set')

    class Meta:
        queryset = Attack.objects.all()
        resource_name = 'attack'
        #includes = []
        #filtering = {
        #}


class PacketResource(ModelResource):
    attacks = fields.ManyToManyField('honeywall.api.AttackResource', 'attacks')

    class Meta:
        queryset = Packet.objects.all()
        resource_name = 'packet'
        filtering = {
            'attack': ALL_WITH_RELATIONS,
        }

    #def dehydrate(self, bundle):
        #bundle.data['payload'] = base64.decodestring(bundle.data['_payload'])
        #del bundle.data['_payload']

        #return bundle
