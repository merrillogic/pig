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
$(function () {
    var all_packets = {
        color: '#000000',
        data: [[0, 53], [1, 48], [2, 55], [3, 44], [4, 58], [5, 54]],
        label: 'all'
    };
    var low_threat = {
        color: '#ffcc00',
        data: [[0, 20], [1, 21], [2, 23], [3, 19], [4, 33], [5, 28]],
        label: 'low threat'
    };
    var medium_threat = {
        color: '#ff6600',
        data: [[0, 5], [1, 7], [2, 6], [3, 10], [4, 9], [5, 4]],
        label: 'medium threat'
    };
    var high_threat = {
        color: '#ff1919',
        data: [[0, 0], [1, 0], [2, 2], [3, 15], [4, 16], [5, 22]],
        label: 'high threat'
    };

    var placeholder = $("#placeholder");
    var plot = $.plot(placeholder, [all_packets, low_threat, medium_threat, high_threat]);

    placeholder.resize(function(){
    });
});

/*
 *Knockout driven dynamic table entries
 */
function attack(attackEntry){
    //attack object, stored in array as a row for the attack table
    var self = this;
    self.aid = ko.observable(attackEntry.id);
    self.attackType = ko.observable(attackEntry.attack_type);
    self.time = ko.observable(attackEntry.start_time);
    self.sourceIp = ko.observable(attackEntry.source_ip);
    self.threatLevel = ko.observable(attackEntry.score);
    
    //level determined to color code table
    if(attackEntry.false_positive){
        self.level = ko.observable("none");
    }else if(attackEntry.score >= 100000){
        self.level = ko.observable("high");
    }else if(attackEntry.score >= 50000){
        self.level = ko.observable("medium");
    }else{
        self.level = ko.observable("low");
    }
};

function updateAttackEntry(attackObj, newAttack){
    //used to update an already existing entry with the given new attack
    attackObj.aid(newAttack.id);
    attackObj.attackType(newAttack.attack_type);
    attackObj.time(newAttack.start_time);
    attackObj.sourceIp(newAttack.source_ip);
    attackObj.threatLevel(newAttack.score);
    
    if(newAttack.false_positive){
        attackObj.level("none");
    }else if(newAttack.score >= 100000){
        attackObj.level("high");
    }else if(newAttack.score >= 50000){
        attackObj.level("medium");
    }else{
        attackObj.level("low");
    }
}

function attacksViewModel(){
    //main attacks model, handles all changes with attack table
    var self = this;
    var attackList = null;
    var jsonAttackObj = getAttacks();
    self.attacks = ko.observableArray([]); //observable array, serves as attack table
    
    //iterate through every attack in the json object, create attack object and store in array
    for(var i = 0; i < jsonAttackObj.objects.length; i++){
        self.attacks.push(new attack(jsonAttackObj.objects[i]));
    }
    
    self.filter_button = function(){
        //called when filter search is enacted
        var filter = removeWhite($('#filter_entry').val());
        var jsonFilteredAttacks = getAttackFiltered(filter); //get filtered attacks
        
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
        $('#filter_entry').val("");

        self.getUpdate();
    }
    
    self.row_click = function(){
        //called when table row is clicked
        var jsonAttack = getAttack(this.aid());
        
        $('#type').text(jsonAttack.attack_type);
        $('#start').text(jsonAttack.start_time);
        $('#end').text(jsonAttack.end_time);
        $('#source').text(jsonAttack.source_ip);
        $('#dest').text(jsonAttack.destination_ip);
        $('#score').text(jsonAttack.score);
    }
    
    self.getUpdate = function(){
        //get most recent attacks
        var jsonAttackObj = getAttacks();
        
        //put into array and thus in table
        for(var i = 0; i < jsonAttackObj.objects.length; i++){
            if(i < self.attacks().length){
                //overwrite existing entries
                updateAttackEntry(self.attacks()[i], jsonAttackObj.objects[i]);
            }else{
                //create new attack row
                self.attacks.push(new attack(jsonAttackObj.objects[i]));
            }
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

function getAttackFiltered(filter){
    //get list of attacks that fit the filter request
    var xmlHttp = new XMLHttpRequest();

    xmlHttp.open("GET", '/api/v1/attack/?' + filter, false);
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


attacksTable = new attacksViewModel();
ko.applyBindings(attacksTable);

//function that updates the table every so often
window.setInterval(function(){
    //only does it if you are not filtering attacks
    if($('#filter_entry').val() == ""){
        attacksTable.getUpdate();
        //alert("updated");
    }
}, 60000);//1 minute
