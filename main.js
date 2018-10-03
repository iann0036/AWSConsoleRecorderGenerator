function stringToColour(str) {
    var hash = 0;
    for (var i = 0; i < str.length; i++) {
      hash = str.charCodeAt(i) + ((hash << 5) - hash);
    }
    var colour = '#';
    for (var i = 0; i < 3; i++) {
      var value = (hash >> (i * 8)) & 0xFF;
      colour += ('00' + value.toString(16)).substr(-2);
    }
    return colour;
}

chrome.runtime.sendMessage(null, {
    "action": "getRequests"
}, null, function(response){
    for (var i in response) {
        console.log(response[i]);
        var potentials_length = response[i]['potentials'].length;
        var first_row = true;
        for (var j in response[i]['potentials']) {
            var potential = response[i]['potentials'][j][0] + "." + response[i]['potentials'][j][2];
            var url = response[i]['url'];
            var potential_color = stringToColour(response[i]['potentials'][j][0]);
            var url_color = stringToColour(response[i]['service']);
            var request_body = response[i]['requestBody'];

            document.getElementById('main').innerHTML += `
            <tr>
            ${first_row ? `<td rowspan="${potentials_length}" style="background-color: ${url_color};">${url}<br />${request_body}</td>` : ''}
            <td style="background-color: ${potential_color};">${potential}</td> 
            <td><button>Accept</button</td>
            </tr>`;
            first_row = false;
        }
    }
});