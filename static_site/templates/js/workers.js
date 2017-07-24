function humanize_shares(bytes, placeholder='???') {
  var sizes = ['', 'K', 'M', 'G', 'T'];
  if (bytes == 0) return placeholder;
  var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
  if (i == 0) return bytes + ' ' + sizes[i];
  return (bytes / Math.pow(1024, i)).toFixed(0) + '' + sizes[i];
};

function jsonWorkerCallback(json) {
  for (var i in json) {
    var worker = json[i]
    var row = $('<tr>')
        .append($('<td>').text(worker['name']))
        .append($('<td>').text(worker['kind']))
        .append($('<td>').text(humanize_shares(worker['maximum_hashrate']).concat(" share/s")))
        .append($('<td>').text(worker['D']))
        .append($('<td>').text(humanize_shares(worker['total_shares'], 0)))
        .append($('<td>').text(humanize_shares(worker['diff1_shares'], 0)))
        .append($('<td>').text(worker['rate']));
      
    $("#workers").find('tbody').append(row);
  }
}

$.ajax({
  url: "http://localhost:8080/workers",
  dataType: "jsonp"
});