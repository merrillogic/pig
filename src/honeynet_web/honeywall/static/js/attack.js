/*
 *attack.js
 *
 *for index.html, for handling row clicks on main table
 *
 *TODO: can't use django objects in javascript file
 */

var aid = $('#aid').text();

//Function that handles clicking of rows on attack table
$(document).ready(function() {
    $('#main_table td').click(function(event) {
        var pid = $(this).parent().children('#idCol').text();
        var jsonPacket = JSON.parse(getPacket(pid));
        
        $('#payload_info').text(jsonPacket._payload);
    });
});

function getPacket(pid){
    var xmlHttp = null;
    
    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/packet/' + pid + '/', false);
    xmlHttp.send(null);
    
    alert(xmlHttp.responseText);
    return xmlHttp.responseText;
}

/*
 *Knockout driven dynamic packet table entry
 */
function packet(packetEntry){
    var self = this;
    self.pid = ko.observable(packetEntry.id);
    self.time = ko.observable(packetEntry.time);
    self.srcIp = ko.observable(packetEntry.source_ip);
    self.srcMac = ko.observable(packetEntry.source_mac);
    self.srcPort = ko.observable(packetEntry.source_port);
    self.destIp = ko.observable(packetEntry.destination_ip);
    self.destMac = ko.observable(packetEntry.destination_mac);
    self.destPort = ko.observable(packetEntry.dest_port);
    self.protocol = ko.observable(packetEntry.protocol);
};

function packetsViewModel(){
    var self = this;
    var jsonPacketObj = JSON.parse(getPackets());
    var packetList = jsonPacketObj.objects;
    self.packets = ko.observableArray([]);
    
    for(var i = 0; i < packetList.length; i++){
        self.packets.push(new packet(packetList[i]));
    }
};

function getPackets(){
    var xmlHttp = null;
    
    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/packet/?attack=' + aid, false);
    xmlHttp.send(null);
    
    return xmlHttp.responseText;
};

ko.applyBindings(new packetsViewModel());
