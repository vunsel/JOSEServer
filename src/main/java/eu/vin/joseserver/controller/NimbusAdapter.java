package eu.vin.joseserver.controller;

import com.nimbusds.jose.*;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.factories.DefaultJWEDecrypterFactory;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.jose4j.base64url.Base64Url;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.text.ParseException;
import java.util.Set;

import static com.nimbusds.jose.EncryptionMethod.A128CBC_HS256;
import static com.nimbusds.jose.JWEAlgorithm.*;
import static com.nimbusds.jose.JWEAlgorithm.ECDH_ES_A128KW;
import static com.nimbusds.jose.jwk.ECKey.*;
import static com.nimbusds.jose.jwk.ECKey.Builder;


public class NimbusAdapter {
    private ECKey ecJWK;

    static class Holder {
        private final static NimbusAdapter instance256 = new NimbusAdapter("P256");
        private final static NimbusAdapter instance384 = new NimbusAdapter("P384");
        private final static NimbusAdapter instance521 = new NimbusAdapter("P521");
    }

    public NimbusAdapter(String curve) {
        // Generate EC key pair with P-256 curve
        KeyPairGenerator gen = null;
        ECKey.Builder eckb = null;
        try {
            if (curve == null || curve.equals("P256")) {
                gen = KeyPairGenerator.getInstance("EC");
                gen.initialize(ECKey.Curve.P_256.toECParameterSpec());
                KeyPair keyPair = gen.generateKeyPair();
                eckb = new ECKey.Builder(ECKey.Curve.P_256, (ECPublicKey) keyPair.getPublic()).privateKey((ECPrivateKey) keyPair.getPrivate());
            } else if (curve.equals("P384")) {
                gen = KeyPairGenerator.getInstance("EC");
                gen.initialize(Curve.P_384.toECParameterSpec());
                KeyPair keyPair = gen.generateKeyPair();
                eckb = new ECKey.Builder(Curve.P_384, (ECPublicKey) keyPair.getPublic()).privateKey((ECPrivateKey) keyPair.getPrivate());
            } else if (curve.equals("P521")) {
                gen = KeyPairGenerator.getInstance("EC");
                gen.initialize(ECKey.Curve.P_521.toECParameterSpec());
                KeyPair keyPair = gen.generateKeyPair();
                eckb = new ECKey.Builder(Curve.P_521, (ECPublicKey) keyPair.getPublic()).privateKey((ECPrivateKey) keyPair.getPrivate());
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        // Convert to JWK format
        // Generate an EC key pair

        this.ecJWK = eckb.build();

//        ECKeyPairGenerator ecGen = null;
//        ecGen = new ECKeyPairGenerator();
//        ecGen.generateKeyPair();
//        KeyPair ecKeyPair = ecGen.generateKeyPair();
//        ECPublicKey ecPublicKey = (ECPublicKey)ecKeyPair.getPublic();
//        ECPrivateKey ecPrivateKey = (ECPrivateKey)ecKeyPair.getPrivate();
//        ecJWK =  new ECKey.Builder(Curve.P_256, ecPublicKey).build();
        try {
            System.out.println("Nimbus private key of curve " + curve + ": " + ecJWK.toECPrivateKey().getS().toString());
//            ECPoint genPoint = ecJWK.getCurve().toECParameterSpec().getGenerator();
//            System.out.println(genPoint.getAffineX() + ", "+ genPoint.getAffineY());
        } catch (JOSEException e) {
            e.printStackTrace();
        }
    }

    public static NimbusAdapter getInstance256() { return NimbusAdapter.Holder.instance256; }

    public static NimbusAdapter getInstance384() {
        return NimbusAdapter.Holder.instance384;
    }

    public static NimbusAdapter getInstance521() {
        return NimbusAdapter.Holder.instance521;
    }

    public String ecdec(String jwt) {
        System.out.println(jwt);
        String result = null;
        JWEObject jweObject;

        try {
            jweObject = JWEObject.parse(jwt);
            ECDHDecrypter jwed = new ECDHDecrypter(ecJWK);
            jweObject.decrypt(jwed);
            result = jweObject.getPayload().toString();
        } catch (java.text.ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    public String ecdhtest(String jwt) {
        String response = null;
        ConfigurableJOSEProcessor cjp = new DefaultJOSEProcessor();
        JWKSet jwkSet = new JWKSet();
        JWKSource keySource = new ImmutableJWKSet(jwkSet);
        JWEAlgorithm jweAlgorithm = ECDH_ES_A128KW;
        EncryptionMethod emjwe = A128CBC_HS256;
        JWEKeySelector keySelector = new JWEDecryptionKeySelector(jweAlgorithm, emjwe, keySource);
        DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWEKeySelector(keySelector);

        JWEDecrypterFactory jd = cjp.getJWEDecrypterFactory();


        return response;
    }

    public String processJWE(String jwt) throws ParseException, JOSEException {
        String result = null;
        JWEDecrypterFactory decrypterFactory = new DefaultJWEDecrypterFactory();
        JWEObject jweObject = JWEObject.parse(jwt);
        JWEDecrypter decrypter = decrypterFactory.createJWEDecrypter(jweObject.getHeader(), this.ecJWK.toPrivateKey());
        jweObject.decrypt(decrypter);
        result = jweObject.getPayload().toString();

//        ConfigurableJOSEProcessor JOSEProcessor = new DefaultJOSEProcessor();
//        ConfigurableJWTProcessor JWTProcessor = new DefaultJWTProcessor();
//        try {
//            EncryptedJWT receivedJWE = EncryptedJWT.parse(jwt);
//            result = receivedJWE.toString();
//            System.out.println(result);
//        } catch (ParseException e) {
//            e.printStackTrace();
//        }
//        try {
//            jweObject = JWEObject.parse(jwt);
//            System.out.println(ecJWK == null);
//            ECDHDecrypter jwed = new ECDHDecrypter(ecJWK);
//            jweObject.decrypt(jwed);
//            result = jweObject.getPayload().toString();
//        } catch (java.text.ParseException e) {
//            e.printStackTrace();
//        } catch (JOSEException e) {
//            e.printStackTrace();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }70299930378711926272062335516270332811038035503912724417083913821979239611208

            return result;


//        String response = null;
//
//
//        EncryptedJWT encryptedJWT = null;
//        JWEDecrypter jwed;
//
//        try {
//            encryptedJWT = EncryptedJWT.parse(jwt);
//            //  encryptedJWT.decrypt(this.ecJWK);
//        } catch (java.text.ParseException e) {
//            // Invalid encrypted JWT encoding
//        }
//        response = encryptedJWT.getPayload().toString();
//        System.out.println(response);
//        return response;
    }

    public String getPublicKeyJweHeader() {
        String curve = ecJWK.getCurve().getName();
        Base64URL x = ecJWK.getX();
        Base64URL y = ecJWK.getY();
        String result = "{\"alg\":\"ECDH-ES\", \"enc\":\"A128GCM\",\"epk\": {\"kty\":\"EC\",\"crv\":\"" + curve + "\",\"x\":\"" + x.toString() + "\",\"y\":\"" + y.toString() + "\"}}";
        return result;
    }
}
