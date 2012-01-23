from django.db import models

class Attack(models.Model):
    classification_time = models.DateField(auto_now_add=True)
    source_ip = models.IPAddressField()
    destination_ip = models.IPAddressField(null=True, blank=True)
    start_time = models.DateField()
    end_time = models.DateField(null=True, blank=True)
    score = models.DecimalField(max_digits=6, decimal_places=3)

class Packet(models.Model):
    source_ip = models.IPAddressField()
    destination_ip = models.IPAddressField(null=True, blank=True)
    source_port = models.IntegerField(null=True, blank=True)
    dest_port = models.IntegerField(null=True, blank=True)
    time = models.DateField()

    # protocal can be 0-255
    protocal = models.IntegerField()
    payload = models.CharField(max_length=65535)

    attack = models.ForeignKey(Attack)
    classification_time = models.DateField(auto_now_add=False, blank=True, null=True)
