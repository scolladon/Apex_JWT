global without sharing class JWT {
  public static final String JWT_HS256 = 'HS256';
  public static final String JWT_RS256 = 'RS256';
  public static final String JWT_NONE = 'none';
  public static final String CRYPTO_HS256 = 'hmacSHA256';
  public static final String CRYPTO_RS256 = 'rsa-sha256';

  private static final INTEGER DEFAULT_VALIDITY = 300;
  private static final String SIGNATURE_SEPARATOR = '.';
  private static final String HEADER_TEMPLATE = '\'{\'"alg":"{0}"\'}\'';
  private static final String CLAIM_TEMPLATE = '\'{\'"iss":"{0}","sub":"{1}","aud":"{2}","iat":"{3}","exp":"{4}"{5}\'}\'';
  private static final String CUSTOM_CLAIM_TEMPLATE = ',"{0}": "{1}"';

  private String header {get {
      return base64URLencode(Blob.valueOf(string.format(HEADER_TEMPLATE,new List<String>{this.alg})));
    }
  }
  private String body {get {
      final List<String> customClaim = new List<String>();
      for (String claimKey : this.customClaims.keySet()) {
        final String claimValue = this.customClaims.get(claimKey);
        if(claimValue != null) {
          customClaim.add(String.format(CUSTOM_CLAIM_TEMPLATE,new List<String>{claimKey,claimValue}));
        }
      }
      final Long rightNow = (dateTime.now().getTime()/1000)+1;
      return base64URLencode(Blob.valueOf(String.format(CLAIM_TEMPLATE,new List<String>{this.iss,this.sub,this.aud,String.valueOf(rightNow),String.valueOf(rightNow + this.validity),String.join(customClaim,'')})));
    }
  }
  private String payload {get {
      return this.header + SIGNATURE_SEPARATOR + this.body;
    }
  }
  private String alg;
  private String iss;
  private String sub;
  private String aud;
  private Integer validity;
  private Map<String,String> customClaims;

  public JWT(final String iss,final String sub,final String aud) {
    this.iss = iss;
    this.sub = sub;
    this.aud = aud;
    this.validity = DEFAULT_VALIDITY;
    this.customClaims = new Map<String,String>();
  }

  public JWT addCustomClaim(final string key, final string value) {
    this.customClaims.put(key,value);
    return this;
  }

  public JWT delCustomClaim(final string key) {
    this.customClaims.remove(key);
    return this;
  }

  public JWT validFor(final Integer newValidity) {
    this.validity = Math.abs(newValidity);
    return this;
  }

  public string getUnsignedToken() {
    return this.getSignedToken(JWT.UnsignedJWT.class,null, true);
  }

  public string getSignedToken(final Type signType, final String encryptKey) {
    return this.getSignedToken(signType,encryptKey, true);
  }

  public string getSignedToken(final Type signType, final String encryptKey, final boolean encodeKey) {
    JWTSignStrategy jwtSignStrat = (JWTSignStrategy) signType.newInstance();
    this.alg = jwtSignStrat.getAlgorithm();
    return jwtSignStrat.getToken(this.payload,encryptKey, encodeKey);
  }

  public static String base64URLencode(final Blob input){
    return encodingUtil.base64Encode(input)
      .replace('/', '_')
      .replace('+', '-')
      .replaceAll('=+$', '');
  }

  public static String getAccessToken(final String tokenEndpoint, final String token) {
    final HttpRequest req = new HttpRequest();
    req.setMethod('POST');
    req.setEndpoint(tokenEndpoint);
    req.setHeader('Content-type', 'application/x-www-form-urlencoded');
    req.setBody('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=' + token);
    final Http http = new Http();
    final HTTPResponse res = http.send(req);
    String access_token = null;
    if ( res.getStatusCode() == 200 ) {
      final System.JSONParser parser = System.JSON.createParser(res.getBody());
      while (parser.nextToken() != null) {
        if ((parser.getCurrentToken() == JSONToken.FIELD_NAME) && (parser.getText() == 'access_token')) {
          parser.nextToken();
          access_token = parser.getText();
          break;
        }
      }
    }
    return access_token;
  }

  // Public in order to make it available to inheritance
  public abstract class  JWTSignStrategy {
    abstract String getToken(final String payload, final String encryptKey, final Boolean encodeKey);
    abstract String getAlgorithm();
  }

  public class HMAC256SignedJWT extends JWTSignStrategy {
    public override String getToken(final String payload, final String encryptKey, final Boolean encodeKey) {
      return payload + SIGNATURE_SEPARATOR + base64URLencode(Crypto.generateMac(CRYPTO_HS256,Blob.valueof(payload),encodeKey ? EncodingUtil.base64Decode(encryptKey) : Blob.valueOf(encryptKey)));
    }
    public override String getAlgorithm() {
      return JWT_HS256;
    }
  }

  public class RSA256SignedJWTWithCert extends JWTSignStrategy {
    public override String getToken(final String payload, final String encryptKey, final Boolean encodeKey) {
      return payload + SIGNATURE_SEPARATOR + base64URLencode(Crypto.signWithCertificate(CRYPTO_RS256, Blob.valueOf(payload), encryptKey));
    }

    public override String getAlgorithm() {
      return JWT_RS256;
    }
  }

  public class RSA256SignedJWTWithPEMencodedP12 extends JWTSignStrategy {
    public override String getToken(final String payload, final String encryptKey, final Boolean encodeKey) {
      return payload + SIGNATURE_SEPARATOR + base64URLencode(Crypto.sign(CRYPTO_RS256, Blob.valueOf(payload), EncodingUtil.base64Decode(encryptKey)));
    }
    public override String getAlgorithm() {
      return JWT_RS256;
    }
  }

  public class UnsignedJWT extends JWTSignStrategy {
    public override String getToken(final String payload, final String encryptKey, final Boolean encodeKey) {
      return payload + SIGNATURE_SEPARATOR;
    }
    public override String getAlgorithm() {
      return JWT_NONE;
    }
  }
}