function signInButton() {
    var authenticationData = {
        Username: document.getElementById("inputUsername").value,
        Password: document.getElementById("inputPassword").value,
    };

    var authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails(authenticationData);
    var poolData = {
        UserPoolId: _config.cognito.userPoolId,
        ClientId: _config.cognito.clientId,
    };
    var userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
    var userData = {
        Username: document.getElementById("inputUsername").value,
        Pool: userPool,
    };

    var cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);

    cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: function (result) {
            var accessToken = result.getAccessToken().getJwtToken();
            newLocation(accessToken)
        },

        onFailure: function (err) {
            alert(err.message || JSON.stringify(err));
        },
    });

    function newLocation(_accessToken) {
        sessionStorage.setItem('token', _accessToken);
        document.location.href = "index.html";
    }
}