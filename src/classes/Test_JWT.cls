@isTest
private class Test_JWT {
  @isTest private static void testUnsignedJWT() {
    JWT tokenGenerator = new JWT(UserInfo.getOrganizationId(),UserInfo.getUserName(),Url.getSalesforceBaseUrl().toExternalForm());
  String token = tokenGenerator.getUnSignedToken();
  }

  @isTest private static void testHMAC256SignedJWT() {
    JWT tokenGenerator = new JWT(UserInfo.getOrganizationId(),UserInfo.getUserName(),Url.getSalesforceBaseUrl().toExternalForm());
  String token = tokenGenerator.getSignedToken(JWT.HMAC256SignedJWT.class,'CcPrZ/O0auMn9x6JxzStLoeSo2ckUG7ymn1MhSlsDM4=',true);
  }

  @isTest private static void testHMAC256SignedJWTUnencoded() {
    JWT tokenGenerator = new JWT(UserInfo.getOrganizationId(),UserInfo.getUserName(),Url.getSalesforceBaseUrl().toExternalForm());
  String token = tokenGenerator.getSignedToken(JWT.HMAC256SignedJWT.class,'CcPrZ/O0auMn9x6JxzStLoeSo2ckUG7ymn1MhSlsDM4=',false);
  }

  @isTest private static void testRSA256SignedJWTWithCert() {
    JWT tokenGenerator = new JWT(UserInfo.getOrganizationId(),UserInfo.getUserName(),Url.getSalesforceBaseUrl().toExternalForm());
  // To make it pass, you have to find a way to create a certificate whith test setup or enable seeAllData
  // String token = jwt.getSignedToken(JWT.RSA256SignedJWTWithCert.class,'your cert name on Salesforce');
  }

  @isTest private static void testRSA256SignedJWTWithPEMencodedP12() {
    JWT tokenGenerator = new JWT(UserInfo.getOrganizationId(),UserInfo.getUserName(),Url.getSalesforceBaseUrl().toExternalForm());
  String token = tokenGenerator.getSignedToken(JWT.RSA256SignedJWTWithPEMencodedP12.class,'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKMpPHwWDqZSox8Fz0NjPz8XnkfiPtCL8ta2cWpqXM0Kle25ZRgwZZlcA8Tuk8silHwqnMB/QCX6gKQpf0DNZpc3OKhmZNgjsTItlCZASL8FMd+jZVBmej9YI7u7BJHhq+y5hvsTkqZkafJLg+hqqzDlUdcE72YrtoRLI7vhJkZ/AgMBAAECgYAA9Bm9Y+ecAzme0crfSvIwrTOomeLiFx9JL/HDvHFkZV5w8DduB8JgPhBrkzVb54zUmO8nlNbMIgWkb/WlbE3gK/fL1dEzlAlkyTX1E/4Aic/PttlJ0baumkzNfzjZE97cA1L+nTk+3RrdzO2cj/rrM/hRpw8uoWOtLc4klAzLYQJBANBzpS9W1xaO7lBCQAo3EH/WGbF30m0lAZM3YX1SedsUz/6PEZfoknJcBrZc670Wcr+Qdx+2JYQ/2JRR3HQIC68CQQDIYOINlsNmDP6dUwsB4TOojOI+yvTy+3aYiZBdjHZ1loWMLMHmtAuwuxnXDJdaYHwMrOf/ZulhE13bXfte1RYxAkEAvfZltrpg0QH4U9PMIIMF2jn2uDAF58ktokd55Idg3TIeSlF/KvybWPRceZw8iNkIQWMZ7CBGGDtG2AOx71vVqQJBAKlSDNK0ygqrAmBIsu10siVEX032TIQib3W4ELCsJ9F3TwRDMdpT2+kMQWqR7jdlfo1rcmNEQANSzSW4Rdg9sZECQDyHWtRXmUIOHOoGYSY8hPo9sByy9ffU2fexTiQkSPQxGp94OlyKBNKcIm9tvhRDcG34JoiAWIXW4mSlV5LMUsY=');
  }


  @isTest private static void testGetAccessToken() {
    Test.setMock(HttpCalloutMock.class, new Test_JWT.Test_JWTHTTPMock());
    JWT.getAccessToken('https://my.endpo.it','myToken');
  }


  @isTest private static void testValidFor() {
    Test.setMock(HttpCalloutMock.class, new Test_JWT.Test_JWTHTTPMock());
    JWT tokenGenerator = new JWT(UserInfo.getOrganizationId(),UserInfo.getUserName(),Url.getSalesforceBaseUrl().toExternalForm());
    tokenGenerator.validFor(60);
  }

  @isTest private static void testCustomClaim() {
    JWT tokenGenerator = new JWT(UserInfo.getOrganizationId(),UserInfo.getUserName(),Url.getSalesforceBaseUrl().toExternalForm());
    final String test = 'test';
    tokenGenerator.addCustomClaim(test,test);
    tokenGenerator.delCustomClaim(test);
    tokenGenerator.addCustomClaim(test,test);
  String token = tokenGenerator.getSignedToken(JWT.UnsignedJWT.class,null);
  }

  public class Test_JWTHTTPMock implements HttpCalloutMock {
  // Implement this interface method
    public HTTPResponse respond(HTTPRequest req) {
      // Create a fake response
      HttpResponse res = new HttpResponse();
      res.setHeader('Content-Type', 'application/json');
      res.setBody('{"access_token":"authent succeeded"}');
      res.setStatusCode(200);
      return res;
    }
  }
}