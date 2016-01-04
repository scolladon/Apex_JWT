JWT
===

Apex implementation of JWT and JWT Bearer flow.   Requires Summer 14 release for RSA-SHA256 support.

Test Coverage : 94.59%

<a href="https://githubsfdeploy.herokuapp.com?owner=ForceComDeveloper&repo=Apex_JWT">
  <img alt="Deploy to Salesforce"
       src="https://raw.githubusercontent.com/afawcett/githubsfdeploy/master/src/main/webapp/resources/img/deploy.png">
</a>


#Unsigned JWT
```
JWT tkGen = new JWT('your issuer','your subject','your audience');
String token = tkGen.getUnSignedToken();
```

#HMAC256 Signed JWT
```
JWT tkGen = new JWT('your issuer','your subject','your audience');
// Base 64 encoded secret
String token = tkGen.getSignedToken(JWT.HMAC256SignedJWT.class,'secret');
// not Base 64 encoded secret
token = tkGen.getSignedToken(JWT.HMAC256SignedJWT.class,'secret',false);
```

#RSA256 Signed JWT with PEM encoded p12
```
JWT tkGen = new JWT('your issuer','your subject','your audience');
String token = tkGen.getSignedToken(JWT.RSA256SignedJWTWithPEMencodedP12.class,'MIICXQIBAAKBgQC4U4Bma7kKa0CLU...pem encoded p12 RSA Key');
```

#RSA256 Signed JWT with Certificate from Setup
```
JWT tkGen = new JWT('your issuer','your subject','your audience');
String token = tkGen.getSignedToken(JWT.RSA256SignedJWTWithCert.class,'JWTKey'); // JWTKey stand for the cert name in Salesforce Setup
```

#Change the default expiration
By default expiration is 5 minutes (300 seconds).   Change it by passing in a validFor in seconds.

```
JWT tkGen = new JWT('your issuer','your subject','your audience');
tkGen.validFor(60); // Return the current object for method chaining
```

#Add or remove custom claim

```
JWT tkGen = new JWT('your issuer','your subject','your audience');
tkGen.addCustomClaim('my custom claim', 'my custom claim value'); // Return the current object for method chaining
tkGen.delCustomClaim('my custom claim'); // Return the current object for method chaining
```

#Bearer Flow
Use the JWT bearer flow for Server to Server applications.

```
JWT.getAccessToken('token_endpoint', tokenPreviouslyGenerated);
```

#Salesforce RSA-256 JWT Bearer Flow
[http://help.salesforce.com/HTViewHelpDoc?id=remoteaccess_oauth_jwt_flow.htm&language=en_US]

```
JWT tkGen = new JWT('your issuer','your subject','https://login.salesforce.com/services/oauth2/token');
String token = tkGen.getSignedToken(JWT.RSA256SignedJWTWithCert.class,'JWTKey'); // JWTKey stand for the cert name in Salesforce Setup
String access_token = JWT.getAccessToken('https://login.salesforce.com/services/oauth2/token', token);
 ```

#Google RSA-256 JWT Bearer Flow
[https://developers.google.com/accounts/docs/OAuth2ServiceAccount]

```
JWT tkGen = new JWT('your issuer','your subject','https://accounts.google.com/o/oauth2/token');
tkGen.addCustomClaim('scope','https://www.googleapis.com/auth/drive');
String token = tkGen.getSignedToken(JWT.RSA256SignedJWTWithPEMencodedP12.class,'MIICXQIBAAKBgQC4U4Bma7kKa0CLU...pem encoded p12 RSA Key');
String access_token = JWT.getAccessToken('https://accounts.google.com/o/oauth2/token', token);
```

#How to test it
Use [http://jwt.io]

#How to extend it
Extend the JWT.JWTSignStrategy class and build your own GetToken and GetAlgorithm method