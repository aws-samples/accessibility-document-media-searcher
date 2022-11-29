//Bucket Configurations

var bucketName = _config.bucket.name;
var bucketRegion = _config.bucket.region;
var identityPoolId = _config.cognito.identityPoolId;

AWS.config.update({
            region: bucketRegion,
            credentials: new AWS.CognitoIdentityCredentials({
            IdentityPoolId: identityPoolId
            })
        });

        var s3 = new AWS.S3({
            apiVersion: '2006-03-01',
            params: {Bucket: bucketName}
    });

function s3upload() {  
          var files = document.getElementById('fileUpload').files;
          if (files) 
          {
              var file = files[0];
              var fileName = file.name;
              var filePath = 'input/' + fileName;
      
              s3.upload({
                              Key: filePath,
                              Body: file,
                              ACL: 'bucket-owner-full-control'
                          }, function(err, data) {
                              if(err) {
                                console.log('error: ' + err)
                                reject('error');
                              }
                              
                              alert('Successfully Uploaded!');
                          }).on('httpUploadProgress', function (progress) {
                              var uploaded = parseInt((progress.loaded * 100) / progress.total);
                              $("progress").attr('value', uploaded);
                          });
          }
};
