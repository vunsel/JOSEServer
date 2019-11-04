package eu.vin.joseserver.controller;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jca.ProviderContext;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.EcKeyUtil;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;
import sun.security.util.KeyUtil;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.interfaces.ECKey;
import java.security.spec.*;

/**
 * JOSE4j Adapter
 * <p>
 * This class is used for creating JSON Web Token using the jose4j library.
 *
 * @author Vincent Unsel
 * @version 1.0
 */

public class Jose4jAdapter {

    static class Holder {
        private final static Jose4jAdapter instance256 = new Jose4jAdapter("P256");
        private final static Jose4jAdapter instance384 = new Jose4jAdapter("P384");
        private final static Jose4jAdapter instance521 = new Jose4jAdapter("P521");
    }

    private final EllipticCurveJsonWebKey ecKeyPair;
    private JsonWebEncryption receivedJWE;

    //private JsonWebEncryption sendJWE;
    private Jose4jAdapter(String curve) {
        ecKeyPair = setPublicKey(curve);
        System.out.println("Jose4j private key of curve " + curve + ": " + ecKeyPair.getEcPrivateKey().getS().toString());
    }

    public static Jose4jAdapter getInstance256() {

        return Jose4jAdapter.Holder.instance256;
    }

    public static Jose4jAdapter getInstance384() {
        return Jose4jAdapter.Holder.instance384;
    }

    public static Jose4jAdapter getInstance521() {
        return Jose4jAdapter.Holder.instance521;
    }

    /**
     * Constructor
     * Set the curve for ECDH-ES to generate servers key pair.
     *
     * @param curve accepts "P256", "P384", "P521"
     */
    private EllipticCurveJsonWebKey setPublicKey(String curve) { //
        EllipticCurveJsonWebKey ecKeyPair = null;
        try {
            if (curve == null || curve.equals("P256")) {
                ecKeyPair = EcJwkGenerator.generateJwk(EllipticCurves.P256);
            } else if (curve.equals("P384")) {
                ecKeyPair = EcJwkGenerator.generateJwk(EllipticCurves.P384);
            } else if (curve.equals("P521")) {
                ecKeyPair = EcJwkGenerator.generateJwk(EllipticCurves.P521);
            } else {
                throw new JoseException("Set curve for generating servers key pair failed.");
            }
            ecKeyPair.setKeyId("Servers Key");
        } catch (JoseException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ecKeyPair;
    }

    public String getPublicKeyJweHeader() {
        String curve = ecKeyPair.getCurveName();
        BigInteger x = ecKeyPair.getECPublicKey().getW().getAffineX();
        BigInteger y = ecKeyPair.getECPublicKey().getW().getAffineY();
//        System.out.println(curve + " x: " + x);
//        System.out.println(curve + " y: " + y);
        String result = "{\"alg\":\"ECDH-ES\", \"enc\":\"A128GCM\",\"epk\": {\"kty\":\"EC\",\"crv\":\"" + curve + "\",\"x\":\"" + Base64Url.encode(x.toByteArray()) + "\",\"y\":\"" + Base64Url.encode(y.toByteArray()) + "\"}}";
        return result;
    }


    public String getPublicJweCompactSerialized() {
//        System.out.println(ecKeyPair.getECPublicKey().getW().getAffineX());
        JsonWebEncryption jwe = new JsonWebEncryption();
        try {
            jwe.setPlaintext("Plaintext");
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
            jwe.setKey(ecKeyPair.getECPublicKey());
            jwe.setIv(new byte[16]);
            return jwe.getCompactSerialization();
        } catch (JoseException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String processJWE(String jwt) throws InvalidJwtException {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        String response = null;

        // Now you can do something with the JWT. Like send it to some other party
        // over the clouds and through the interwebs.
        //System.out.println("JWT: " + jwt);


        // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
        // be used to validate and process the JWT.
        // The specific validation requirements for a JWT are context dependent, however,
        // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
        // and audience that identifies your system as the intended recipient.
        // It is also typically good to allow only the expected algorithm(s) in the given context

        AlgorithmConstraints jweAlgConstraints = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                KeyManagementAlgorithmIdentifiers.ECDH_ES,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A192KW,
                KeyManagementAlgorithmIdentifiers.ECDH_ES_A256KW);

        AlgorithmConstraints jweEncConstraints = new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST,
                ContentEncryptionAlgorithmIdentifiers.AES_128_GCM,
                ContentEncryptionAlgorithmIdentifiers.AES_192_GCM,
                ContentEncryptionAlgorithmIdentifiers.AES_256_GCM,
                ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256,
                ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384,
                ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512
        );
        ProviderContext context = new ProviderContext();
        context.getGeneralProviderContext().setGeneralProvider("BC");
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
//                .setRequireExpirationTime() // the JWT must have an expiration time
//                .setMaxFutureValidityInMinutes(300) // but the  expiration time can't be too crazy
//                .setRequireSubject() // the JWT must have a subject claim
//                .setExpectedIssuer("sender") // whom the JWT needs to have been issued by
//                .setExpectedAudience("receiver") // to whom the JWT is intended for
                .setJweAlgorithmConstraints(jweAlgConstraints) // limits acceptable encryption key establishment algorithm(s)
                .setJweContentEncryptionAlgorithmConstraints(jweEncConstraints) // limits acceptable content encryption algorithm(s)
                .setDecryptionKey(ecKeyPair.getPrivateKey()) // decrypt with the receiver's private key
               // .setJweProviderContext(context)
                .build(); // create the JwtConsumer instance
        //  Validate the JWT and process it to the Claims
//        JwtContext jwtContext = jwtConsumer.process(jwt);
//        jwtContext.getJoseObjects().get(0);

        JwtContext jwtContext = jwtConsumer.process(jwt);
        jwtConsumer.processContext(jwtContext);
        //JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
        response = "JWT validation succeeded! " + jwtContext.getJoseObjects().toString();


        return response;
    }

    public void receiveToken(String token) {

        try {
            receivedJWE.setCompactSerialization(token);
            System.out.println("Received JWE: " + receivedJWE);
        } catch (JoseException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String sendJWE() {
        return receivedJWE.toString();
    }

//    public String sendToken() {
//
// Produce JWT ////////////////////////////////////////////////////////////////////////////
//        EllipticCurveJsonWebKey reECJWK = (EllipticCurveJsonWebKey) receivedJWE.getKey();
//        reECJWK.setKeyId("Received key");
//
//
//        JwtClaims claims = new JwtClaims();
//        claims.setIssuer("sender");  // who creates the token and signs it
//        claims.setAudience("receiver"); // to whom the token is intended to be sent
//        claims.setExpirationTimeMinutesInTheFuture(10); // time when the token will expire (10 minutes from now)
//        claims.setGeneratedJwtId(); // a unique identifier for the token
//        claims.setIssuedAtToNow();  // when the token was issued/created (now)
//        claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
//        claims.setSubject("subject"); // the subject/principal is whom the token is about
//        claims.setClaim("email","mail@example.com"); // additional claims/attributes about the subject can be added
//        List<String> groups = Arrays.asList("group-1", "other-group", "group-3");
//        claims.setStringListClaim("groups", groups); // multi-valued claims work too and will end up as a JSON array
//10074737035401637603640447131395085941296250671199747157647610830495675366630
//351472946986599656177585351537079864668259788179024239264163619432577119340572
//        // The outer JWT is a JWE
//        JsonWebEncryption jwe = new JsonWebEncryption();
//
//        // The output of the ECDH-ES key agreement will encrypt a randomly generated content encryption key
//        jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.ECDH_ES_A128KW);
//
//        // The content encryption key is used to encrypt the payload
//        // with a composite AES-CBC / HMAC SHA2 encryption algorithm
//        String encAlg = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256;
//
//        jwe.setEncryptionMethodHeaderParameter(encAlg);
//
//        // We encrypt to the receiver using their public key
//        jwe.setKey(ecKeyPair.getPublicKey());
//        jwe.setKeyIdHeaderValue(ecKeyPair.getKeyId());
//
//        // A nested JWT requires that the cty (Content Type) header be set to "JWT" in the outer JWT
//        jwe.setContentTypeHeaderValue("JWT");
//
//        //Payload to encrypt.
//        jwe.setPayload("plaintext");
//        // Produce the JWE compact serialization, which is the complete JWT/JWE representation,
//        // which is a string consisting of five dot ('.') separated
//        // base64url-encoded parts in the form Header.EncryptedKey.IV.Ciphertext.AuthenticationTag
//        String jwt = null;
//        try {
//            jwt = jwe.getCompactSerialization();
//        } catch(JoseException e) {
//            e.printStackTrace();
//        }
////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//        try {
//            System.out.println(sendJWE);
//            return sendJWE.getCompactSerialization();
//        } catch (JoseException e) {
//            e.printStackTrace();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return "No valid token to serialize.";
//    }
}

