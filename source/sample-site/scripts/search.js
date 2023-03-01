// Update this variable to point to your domain.
var apigatewayendpoint = _config.apigatewayendpoint;
var loadingdiv = $('#loading');
var noresults = $('#noresults');
var resultdiv = $('#results');
var searchbox = $('input#search');
var timer = 0;
var authToken = sessionStorage.getItem('token'); 
// Executes the search function 250 milliseconds after user stops typing
searchbox.keyup(function () {
  clearTimeout(timer);
  timer = setTimeout(search, 250);
});

async function search() {
  // Clear results before searching
  noresults.hide();
  resultdiv.empty();
  loadingdiv.show();
  // Get the query from the user
  let query = searchbox.val();
  // Only run a query if the string contains at least three characters
  if (query.length > 2) {
    // Make the HTTP request with the query as a parameter and wait for the JSON results
    // let response = await $.get(apigatewayendpoint, { q: query, size: 25, Authorization: authToken}, 'json');
    let response = await $.ajax({
      url: apigatewayendpoint,
      data: { q: query, size: 25},
      headers: {
        'Authorization':authToken,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization'
      },
      dataType: 'json'
    });
    // Get the part of the JSON response that we care about
    let results = response['hits']['hits'];
    console.log(response)
    if (results.length > 0) {
      loadingdiv.hide();
      // Iterate through the results and write them to HTML
      resultdiv.append('<p id=found-result>Results found: ' + results.length + '.</p>');
      for (var item in results) {
        let name = results[item]._source.name;
        let textS3File = results[item]._source.textS3File;
        let mediaS3File = results[item]._source.mediaS3Key;
        let media = results[item]._source.media;
        let text = results[item]._source.text;
        let datetime = results[item]._source.datetime;
        let shortText = text.substring(0, 500)+"...";
        

        // Construct the full HTML string that we want to append to the div
        resultdiv.append('<div class="result">' +
        '<div><h2><a href=../' + mediaS3File + '>' + name +
        '</a></h2><p>Data Hora: ' + datetime +
        '<br /></h2><a href=../' + textS3File +'> Link text </a> |' +
        '</a></h2><a href=../' + mediaS3File +'> Link Mídia </a>' +
        '<br /><br />' + shortText + '</p></div></div>');
      }
    } else {
      noresults.show();
    }
  }
  loadingdiv.hide();
}

// Tiny function to catch images that fail to load and replace them
function imageError(image) {
  image.src = 'images/no-image.png';
}
