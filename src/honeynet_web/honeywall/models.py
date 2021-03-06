import base64
from django.db import models
from django.db.models.signals import pre_save, post_delete, post_save
from django.dispatch.dispatcher import receiver
from macaddress.fields import MACAddressField

class RecordCount(models.Model):
    record_count = models.IntegerField(default=0)
    CHOICES = (
                ('packets', 'packet count'),
                ('attacks_low', 'low priorty attack count'),
                ('attacks_medium', 'medium priorty attack count'),
                ('attacks_high', 'high priorty attack count'),
                ('attacks_false', 'false positive count'),
              )
    record = models.CharField(max_length=20, choices=CHOICES)

class ARPRecord(models.Model):
    ip = models.IPAddressField()
    mac = MACAddressField()

    def __unicode__(self):
        return unicode(self.ip) + u': ' + unicode(self.mac)

    class Meta:
        unique_together = ('ip', 'mac')


class Attack(models.Model):
    classification_time = models.DateTimeField(auto_now_add=True)
    source_ip = models.IPAddressField()
    destination_ip = models.IPAddressField(null=True, blank=True)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField(null=True, blank=True)
    score = models.IntegerField()

    ATTACK_CHOICES = (
                        ( 'sql', 'SQL Injection' ),
                        ( 'pass', 'Password Cracking' ),
                        ( 'dos', 'Denial of Service' ),
                        ( 'mail', 'Mail' ),
                        ( 'mitm', 'Man in the Middle' )
                     )
    attack_type = models.CharField(max_length=4, choices=ATTACK_CHOICES)
    false_positive = models.BooleanField(default=False)

    @property
    def threat_level(self):
        if not self.score or self.false_positive:
            return 'none'
        elif self.score < 50000:
            return 'low'
        elif self.score < 100000:
            return 'medium'
        elif self.score >= 100000:
            return 'high'

    class Meta:
        # order newest first -- but by what measure?
        ordering = ['-start_time']
        unique_together = ('start_time', 'source_ip', 'attack_type')

    def __str__(self):
        out = "Attack type: "+str(self.attack_type)+'\n'+\
              "Classification time: "+str(self.classification_time)+'\n'+\
              "Source IP: "+str(self.source_ip)+'\n'+\
              "Destination IP: "+str(self.destination_ip)+'\n'+\
              "Start time: "+str(self.start_time)+'\n'+\
              "End time: "+str(self.end_time)+'\n'+\
              "Score: "+str(self.score)+'\n'+\
              "False Positive?: "+str(self.false_positive)
        return out

class TrafficPoint(models.Model):
    time = models.DateTimeField()
    num_all_packets = models.IntegerField()
    num_high_packets = models.IntegerField()
    num_medium_packets = models.IntegerField()
    num_low_packets = models.IntegerField()

    class Meta:
        #order newest first
        unique_together = ('time',)
        ordering = ['-time']

class Packet(models.Model):
    source_ip = models.IPAddressField()
    destination_ip = models.IPAddressField(null=True, blank=True)
    source_port = models.IntegerField(null=True, blank=True)
    dest_port = models.IntegerField(null=True, blank=True)
    source_mac = MACAddressField()
    destination_mac = MACAddressField(null=True, blank=True)

    packet_id = models.IntegerField(null=True, blank=True)
    time = models.DateTimeField()

    # protocol can be 0-255
    protocol = models.IntegerField(null=True, blank=True)

    attacks = models.ManyToManyField(Attack, null=True, blank=True)
    classification_time = models.DateTimeField(auto_now_add=False, blank=True, null=True)

    traffic_point = models.ForeignKey(TrafficPoint, blank=True, null=True)

    # store payload as encoded data
    _payload = models.TextField(db_column='payload', blank=True)

    @property
    def payload(self):
        return base64.decodestring(self._payload)

    @payload.setter
    def payload(self, data):
        self._payload = base64.encodestring(data)

    @payload.deleter
    def payload(self):
        self._x = ''


    class Meta:
        # order newest first
        ordering = ['-time']
        unique_together = ('time', 'source_ip')

    def __unicode__(self):
        out = u"Source IP: "+unicode(self.source_ip)+u'\n'+\
              u"Destination IP: "+unicode(self.destination_ip)+u'\n'+\
              u"Source Port: "+unicode(self.source_port)+u'\n'+\
              u"Destination Port: "+unicode(self.dest_port)+u'\n'+\
              u"Source MAC: "+unicode(self.source_mac)+u'\n'+\
              u"Destination MAC: "+unicode(self.destination_mac)+u'\n'+\
              u"Time: "+unicode(self.time)+u'\n'+\
              u"Protocol: "+unicode(self.protocol)+u'\n'+\
              u"Payload: "+unicode(self.payload)+u'\n'+\
              u"Attack: "+unicode(self.attacks)+u'\n'+\
              u"Classification time: "+unicode(self.classification_time)
        return out

@receiver(pre_save, sender=Packet, dispatch_uid='packet_pre_save')
def update_packet_count(sender, instance, **kwargs):
    if instance.id:
        # already existed oh snap
        pass
    else:
        c, created = RecordCount.objects.get_or_create(record='packets')
        c.record_count += 1
        c.save()

@receiver(post_delete, sender=Packet, dispatch_uid='packet_post_delete')
def update_packet_count_on_delete(sender, instance, **kwargs):
    c, created = RecordCount.objects.get_or_create(record='packets')
    c.record_count -= 1
    c.save()
