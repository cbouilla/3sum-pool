function bytesToSize(bytes) {
  var sizes = ['', 'K', 'M', 'G', 'T'];
  if (bytes == 0) return 'n/a';
  var i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
  if (i == 0) return bytes + ' ' + sizes[i];
  return (bytes / Math.pow(1024, i)).toFixed(0) + '' + sizes[i];
};

function jsonNavbarCallback(json){
  $("#n_miners").html(json['miners']);
  $("#rate").html(json['rate'].toFixed(1));
  $("#shares").html(bytesToSize(json['shares']));
  $(".progress-bar").attr("aria-valuenow", json['shares'] / 12e9)
  $("#gauge-label").html((100 * json['shares'] / 12e9).toFixed(0))
}

$.ajax({
  url: "http://localhost:8080/navbar",
  dataType: "jsonp"
});