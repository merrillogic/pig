$(function () {
    var d1 = [];
    for (var i = 0; i < 14; i += 0.5)
        d1.push([i, Math.sin(i)]);

    var d2 = [[0, 3], [4, 8], [8, 5], [9, 13]];

    // a null signifies separate line segments
    var d3 = [[0, 12], [7, 12], null, [7, 2.5], [12, 2.5]];

    var placeholder = $("#placeholder");
    
    var plot = $.plot(placeholder, [d1, d2, d3]);

    placeholder.resize(function () {
    });
});

$(document).ready(function() {
    $('#attackTable tr').click(function() {
        $('#type').text("Testing");
    });
});
