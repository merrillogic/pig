/*
 *index.js
 *
 *for index.html, for plotting chart in upper row and handling
 *row clicks on main table
 *
 */

/*
 *Flot driven dynamic plot
 */
function plotChart() {
    var jsonTrafficPoints = getTrafficPoints();
    var allPackets = [];
    var highPackets = [];
    var mediumPackets = [];
    var lowPackets = [];
    var times = [];
    var time = null;
    
    for(var i = jsonTrafficPoints.objects.length - 1; i >= 0; i--){
        //append +00:00 to ensure times match up with database showing up
        time = Date.parse(jsonTrafficPoints.objects[i].time + "+00:00");
        //alert(Date.parse(time));
        times.push(time);
        allPackets.push([time, jsonTrafficPoints.objects[i].num_all_packets]);
        highPackets.push([time, jsonTrafficPoints.objects[i].num_high_packets]);
        mediumPackets.push([time, jsonTrafficPoints.objects[i].num_medium_packets]);
        lowPackets.push([time, jsonTrafficPoints.objects[i].num_low_packets]);
    }
    
    var all_packets = {
        color: '#000000',
        data: allPackets,
        label: 'all',
        lines: { show: true },
        points: { show: true }
    };
    var low_threat = {
        color: '#ffcc00',
        data: lowPackets,
        label: 'low threat',
        lines: { show: true },
        points: { show: true }
    };
    var medium_threat = {
        color: '#ff6600',
        data: mediumPackets,
        label: 'medium threat',
        lines: { show: true },
        points: { show: true }
    };
    var high_threat = {
        color: '#ff1919',
        data: highPackets,
        label: 'high threat',
        lines: { show: true },
        points: { show: true }
    };
    
    var options = {
        xaxis: {
            mode: "time",
            timeformat: "%m/%d\n%H:%M",
            tick: times,
            tickSize: [1, "hour"],
            min: times[0]
        }
    }

    var placeholder = $("#plot");
    var plot = $.plot(placeholder, [all_packets, low_threat, medium_threat, high_threat], options);

    placeholder.resize(function(){
    });
}

function getTrafficPoints(){
    //get list of points using a GET request to server
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/plot_data/?format=json', false);
    xmlHttp.send(null);

    return JSON.parse(xmlHttp.responseText);
}

/*
 *Knockout driven dynamic table entries
 */
 
/*Attack Table Objects*/
function attack(attackEntry){
    //attack object, stored in array as a row for the attack table
    var self = this;
    self.aid = ko.observable(attackEntry.id);
    self.attackType = ko.observable(attackEntry.attack_type);
    self.startTime = ko.observable(attackEntry.start_time);
    self.endTime = ko.observable(attackEntry.end_time);
    self.sourceIp = ko.observable(attackEntry.source_ip);
    self.destinationIp = ko.observable(attackEntry.destination_ip);
    self.score = ko.observable(attackEntry.score);

    self.link = ko.observable('/attack/' + self.aid());
    
    //level determined to color code table
    self.level = ko.observable(attackEntry.threat_level);
};

function updateAttackEntry(attackObj, newAttack){
    //used to update an already existing entry with the given new attack
    attackObj.aid(newAttack.id);
    attackObj.attackType(newAttack.attack_type);
    attackObj.startTime(newAttack.start_time);
    attackObj.endTime(newAttack.end_time);
    attackObj.sourceIp(newAttack.source_ip);
    attackObj.destinationIp(newAttack.destination_ip);
    attackObj.score(newAttack.score);
    attackObj.level(newAttack.threat_level);
    attackObj.link('/attack/' + attackObj.aid());
};

/*Traffic Analysis Objects*/
function traffic(attackName, trafficEntry){
    var self = this;
    
    self.attackType = ko.observable(attackName);
    self.lastOccurrence = ko.observable(trafficEntry.last_attack);
    self.averageScore = ko.observable(roundToNearestHundreth(trafficEntry.average_score));
    self.highScore = ko.observable(trafficEntry.high_score);
    self.perAttack = ko.observable(convertToPercent(trafficEntry.percent_attacks));
    self.perTraffic = ko.observable(convertToPercent(trafficEntry.percent_traffic));
    self.perFalsePositives = ko.observable(convertToPercent(trafficEntry.percent_false_positives));
}

function updateTrafficEntry(trafficObj, attackName, newTraffic){
    trafficObj.attackType(attackName);
    trafficObj.lastOccurrence(newTraffic.last_attack);
    trafficObj.averageScore(roundToNearestHundreth(newTraffic.average_score));
    trafficObj.highScore(newTraffic.high_score);
    trafficObj.perAttack(convertToPercent(newTraffic.percent_attacks));
    trafficObj.perTraffic(convertToPercent(newTraffic.percent_traffic));
    trafficObj.perFalsePositives(convertToPercent(newTraffic.percent_false_positives));
}

function convertToPercent(string){
    var original = parseFloat(string);
    var num = null;
    var result = '';
    
    if(original == original){
        //string actually contains a numeric value
        num = Math.round(original * 10000) / 100;
        
        if(num == 0 && original > 0)
            result = '~'
        
        result += num + '%';
        return result;
    }else{
        //non numeric string passed in
        return string
    }
}

function roundToNearestHundreth(string){
    var original = parseFloat(string);
    var num = null;
    
    if(original == original){
        //string contained a numeric value
        num = Math.round(original * 100) / 100;
        return num;
    }else{
        return string;
    }
}

function attacksViewModel(){
    //main attacks model, handles all changes with attack table
    var self = this;
    var jsonAttackObj = getAttacks();
    var jsonTrafficObj = getTrafficAnalysis()

    self.attacks = ko.observableArray([]); //observable array, serves as attack table
    self.traffics = ko.observableArray([]); //observable array, serves as traffic table
    
    self.nextPage = ko.observable(jsonAttackObj.meta.next);
    self.previousPage = ko.observable(jsonAttackObj.meta.previous);

    //iterate through every attack in the json object, create attack object and store in array
    for(var i = 0; i < jsonAttackObj.objects.length; i++){
        self.attacks.push(new attack(jsonAttackObj.objects[i]));
    }
    
    for(var entry in jsonTrafficObj){
        self.traffics.push(new traffic(entry, jsonTrafficObj[entry]));
    }

    self.get_previous = function(){
        self.attack_from_url(self.previousPage());
    }
    self.get_next = function(){
        self.attack_from_url(self.nextPage());
    }

    self.filter_button = function(){
        //called when filter search is enacted
        var filter = removeWhite($('#form_entry').val());
        var url = getFilterURL(filter);
        self.attack_from_url(url);
    }

    self.attack_from_url = function(url){
        var jsonFilteredAttacks = getAttacksFromURL(url); //get filtered attacks
        self.nextPage(jsonFilteredAttacks.meta.next);
        self.previousPage(jsonFilteredAttacks.meta.previous);

        if(jsonFilteredAttacks.objects.length <= self.attacks().length){
            //there are more attacks currently in the table than needed
            for(var i = 0; i < self.attacks().length; i++){
                //if at this index, an attack exists within the json object array
                if(i < jsonFilteredAttacks.objects.length){
                    //change the entry to reflect the filtered attack that was retrieved
                    updateAttackEntry(self.attacks()[i], jsonFilteredAttacks.objects[i]);
                }else{
                    //done with filtered attacks, but entries are left in the array so remove them
                    self.attacks.remove(self.attacks()[i]);
                    i--;
                }
            }
        }else{
            //there are more filtered attacks than we can currently fit in the table
            for(var i = 0; i < jsonFilteredAttacks.objects.length; i++){
                //if at this index, a table entry exists
                if(i < self.attacks().length){
                    //change the entry to reflect the filtered attack that was retrieved
                    updateAttackEntry(self.attacks()[i], jsonFilteredAttacks.objects[i]);
                }else{
                    //no more room in the table, create new row
                    self.attacks.push(new attack(jsonFilteredAttacks.objects[i]));
                }
            }
        }
    };

    self.clear_button = function(){
        //called when clear button is clicked
        $('#form_entry').val("");

        self.getUpdate();
    }

    self.row_click = function(){
        window.location = this.link()
    }

    self.getUpdate = function(){
        //get most recent json objects
        var jsonAttackObj = getAttacks();
        var jsonTrafficObj = getTrafficAnalysis()
        var i = 0;
        
        //put into array and thus in table
        for(i = 0; i < jsonAttackObj.objects.length; i++){
            if(i < self.attacks().length){
                //overwrite existing entries
                updateAttackEntry(self.attacks()[i], jsonAttackObj.objects[i]);
            }else{
                //create new attack row
                self.attacks.push(new attack(jsonAttackObj.objects[i]));
            }
        }
        
        i = 0;
        
        //update traffic entries
        for(entry in jsonTrafficObj){
            updateTrafficEntry(self.traffics()[i], entry, jsonTrafficObj[entry]);
            i++;
        }
    }
};

function getAttack(aid){
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/attack/' + aid + '/?format=json', false);
    xmlHttp.send(null);

    return JSON.parse(xmlHttp.responseText);
}

function getAttacks(){
    //get list of attacks using a GET request to server
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/attack/?format=json', false);
    xmlHttp.send(null);

    return JSON.parse(xmlHttp.responseText);
}

function getFilterURL(filter){
    //build URL for filter
    return "/api/v1/attack?format=json&" + filter;
}

function getAttacksFromURL(url){
    //get list of attacks from url
    var xmlHttp = new XMLHttpRequest();

    xmlHttp.open("GET", url, false);
    xmlHttp.send(null);

    return JSON.parse(xmlHttp.responseText);
}

function getTrafficAnalysis(){
    var xmlHttp = null;

    xmlHttp = new XMLHttpRequest();
    xmlHttp.open("GET", '/api/v1/traffic_analysis/?format=json', false);
    xmlHttp.send(null);
    
    return JSON.parse(xmlHttp.responseText);
}

function removeWhite(string){
    //removes all white spaces from given string
    var newString = "";

    for(var i = 0; i < string.length; i++){
        if(string[i] != " "){
            newString += string[i];
        }
    }

    return newString;
}


attacksViewTable = new attacksViewModel();
ko.applyBindings(attacksViewTable);
plotChart();

//function that updates the table every so often
window.setInterval(function(){
    //only does it if you are not filtering attacks
    if($('#form_entry').val() == ""){
        attacksViewTable.getUpdate();
        //alert("updated");
    }
    
    plotChart();
}, 60000);//1 minute
