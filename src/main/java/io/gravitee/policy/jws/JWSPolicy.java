/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.jws;

import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.stream.TransformableRequestStreamBuilder;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.exception.TransformationException;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.jws.configuration.JWSPolicyConfiguration;
import io.gravitee.policy.jws.utils.JsonUtils;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import sun.security.x509.*;

import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
*/
public class JWSPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWSPolicy.class);
    private static final String DEFAULT_KID = "default";
    private static final String PUBLIC_KEY_PROPERTY = "policy.jws.kid.%s";
    private static final Pattern SSH_PUB_KEY = Pattern.compile("ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)");
    private static final String PEM_EXTENSION = ".pem";
    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";
    private static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----";
    private static final String END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----";

    /**
     * The "typ" value "JOSE+JSON" can be used by applications to indicate that
     * this object is a JWS or JWE using the JWS JSON Serialization or the JWE JSON Serialization.
     */
    private static final String JOSE_JSON_TYP = "JOSE+JSON";
    /**
     * The "typ" value "JOSE" can be used by applications to indicate that
     * this object is a JWS or JWE using the JWS Compact Serialization or
     * the JWE Compact Serialization.
     */
    private static final String JSON_TYP = "JSON";
    private static final String[] AUTHORIZED_TYPES = new String[] { JSON_TYP, JOSE_JSON_TYP};

    /**
     * The "cty" (content type) Header Parameter is used by JWS applications
     * to declare the MIME Media Type of the secured content (the payload)
     * To keep messages compact in common situations, it is RECOMMENDED that
     * senders omit an "application/"
     */
    private static final String JSON_CTY = "json";

    private static final String APPLICATION_PREFIX = "application/";

    private JWSPolicyConfiguration jwsPolicyConfiguration;

    public JWSPolicy(JWSPolicyConfiguration jwsPolicyConfiguration) {
        this.jwsPolicyConfiguration = jwsPolicyConfiguration;
    }

    @OnRequestContent
    public ReadWriteStream onRequestContent(Request request, ExecutionContext executionContext, PolicyChain policyChain) {
        return TransformableRequestStreamBuilder
                .on(request)
                .contentType(MediaType.APPLICATION_JSON)
                .transform(map(executionContext, policyChain))
                .build();
    }

    Function<Buffer, Buffer> map(ExecutionContext executionContext, PolicyChain policyChain) {
        return input -> {
            try {
                DefaultClaims jwtClaims = validateJsonWebToken(input.toString(), executionContext);
                return Buffer.buffer(JsonUtils.writeValueAsString(jwtClaims));
            } catch (UnsupportedJwtException | ExpiredJwtException | MalformedJwtException
                    | SignatureException | IllegalArgumentException | CertificateException ex) {
                LOGGER.error("Failed to decoding JWS token", ex);
                policyChain.streamFailWith(PolicyResult.failure(HttpStatusCode.UNAUTHORIZED_401, "Unauthorized"));
                return null;
            } catch (Exception ex) {
                LOGGER.error("Error occurs while decoding JWS token", ex);
                throw new TransformationException("Unable to apply JWS decode: " + ex.getMessage(), ex);
            }
        };
    }

    /**
     * This method is used to validate the JWT Token.
     * @param jwt String Json Web Token
     * @return DefaultClaims claims extracted from JWT body
     */
    private DefaultClaims validateJsonWebToken(String jwt, ExecutionContext executionContext) throws CertificateException {
        // 1 : decode jwt with the given gravitee.yml public key
        JwtParser jwtParser = Jwts.parser();
        SigningKeyResolver signingKeyResolver = getSigningKeyResolverByGatewaySettings(executionContext);
        jwtParser.setSigningKeyResolver(signingKeyResolver);
        final Jwt token = jwtParser.parse(jwt);

        // 2 : check if typ header is present and equals to the specified values (currently JSON and JOSE+JSON)
        String type = (String) token.getHeader().get(io.gravitee.policy.jws.utils.JwsHeader.TYPE);
        if (type != null && !type.isEmpty() && !Arrays.asList(AUTHORIZED_TYPES).contains(type.toUpperCase())) {
            throw new MalformedJwtException("Only " + AUTHORIZED_TYPES + " JWS typ header are authorized but was " + type);
        }

        // 3 : check if cty header is present and equals to the specified values (currently json)
        String cty = (String) token.getHeader().get(io.gravitee.policy.jws.utils.JwsHeader.CONTENT_TYPE);
        if (cty != null && !cty.isEmpty()) {
            cty = cty.toLowerCase().replaceAll(APPLICATION_PREFIX, "");
            if (!JSON_CTY.equals(cty)) {
                throw new MalformedJwtException("Only " + JSON_CTY + " JWS cty header is authorized but was " + cty);
            }
        }

        // 4 : retrieve certificate from x5c JWS Header
        // The certificate or certificate chain is represented as a JSON array of
        // certificate value strings.  Each string in the array is base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
        List<String> x5cList = (List<String>) token.getHeader().get(io.gravitee.policy.jws.utils.JwsHeader.X509_CERT_CHAIN);
        String[] x5c = x5cList.toArray(new String[x5cList.size()]);
        if (x5c == null || x5c.length == 0) {
            throw new MalformedJwtException("X5C JWS Header is missing");
        }

        // extract certificate from X5C JWSHeader
        X509Certificate cert = extractCertificateFromX5CHeader(x5c);

        // 5 : compare certificate public key with given public key
        // Verifies that this certificate was signed using the private key that corresponds to the specified public key.
        RSAPublicKey givenPublicKey = (RSAPublicKey) signingKeyResolver.resolveSigningKey((JwsHeader) token.getHeader(), (Claims) token.getBody());
        RSAPublicKey certificatePublicKey = (RSAPublicKey) cert.getPublicKey();

        if (certificatePublicKey.getPublicExponent().compareTo(givenPublicKey.getPublicExponent()) != 0) {
            throw new SignatureException("Certificate public key exponent is different compare to the given public key exponent");
        }

        if (certificatePublicKey.getModulus().compareTo(givenPublicKey.getModulus()) != 0) {
            throw new SignatureException("Certificate public key modulus is different compare to the given public key modulus");
        }

        // 6 : check certificate validity (not before and not after settings)
        if (jwsPolicyConfiguration.isCheckCertificateValidity()) {
            cert.checkValidity();
        }

        // 7 : check if certificate has been revoked via the certificate revocation list (CRL)
        if (jwsPolicyConfiguration.isCheckCertificateRevocation()) {
            validateCRLSFromCertificate(cert);
        }

        return (DefaultClaims) token.getBody();
    }

    /**
     * Return a SigingKeyResolver which will read kid claims header value in order to get the associated public key.
     * The associated public keys are set into the gateway settings and retrieved thanks to ExecutionContext.
     * @param executionContext ExecutionContext
     * @return SigningKeyResolver
     */
    private SigningKeyResolver getSigningKeyResolverByGatewaySettings(ExecutionContext executionContext) {
        return new SigningKeyResolverAdapter() {
            @Override
            public Key resolveSigningKey(JwsHeader header, Claims claims) {
                String keyId = header.getKeyId(); //or any other field that you need to inspect
                if (keyId == null || keyId.isEmpty()) {
                    keyId = DEFAULT_KID;
                }
                Environment env = executionContext.getComponent(Environment.class);
                String publicKey = env.getProperty(String.format(PUBLIC_KEY_PROPERTY, keyId));
                if(publicKey==null || publicKey.trim().isEmpty()) {
                    return null;
                }
                // Public key can be either "ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*)" string format
                // or file path to the Certificate PEM file
                Matcher m = SSH_PUB_KEY.matcher(publicKey);
                if (m.matches()) {
                    return parsePublicKey(publicKey);
                } else if (publicKey.endsWith(PEM_EXTENSION)) {
                    try {
                        return extractPublicKeyFromPEMFile(publicKey);
                    } catch (Exception e) {
                        LOGGER.error("Failed to load PEM file", e);
                        return null;
                    }
                } else {
                    return null;
                }
            }
        };
    }

    public void validateCRLSFromCertificate(X509Certificate certificate, BigInteger serialNumber) throws CertificateException {
        X509CRLEntry revokedCertificate = null;
        X509CRL crl;
        X509CertImpl x509Cert = (X509CertImpl) certificate;
        CRLDistributionPointsExtension crlDistroExtension = x509Cert.getCRLDistributionPointsExtension();
        if (crlDistroExtension != null) {
            try {
                ArrayList<DistributionPoint> distributionPoints = (ArrayList<DistributionPoint>) crlDistroExtension.get(CRLDistributionPointsExtension.POINTS);
                Iterator<DistributionPoint> iterator = distributionPoints.iterator();
                boolean hasError = false;
                while (iterator.hasNext()) {
                    if (revokedCertificate != null) { break; }
                    GeneralNames distroName = iterator.next().getFullName();
                    for (int i = 0; i < distroName.size(); ++i) {
                        hasError = false;
                        if (revokedCertificate != null) { break; }
                        DataInputStream inStream = null;
                        try {
                            URI uri = ((URIName) distroName.get(i).getName()).getURI();
                            URL url = new URL(uri.toString());
                            URLConnection connection = url.openConnection();
                            inStream = new DataInputStream(connection.getInputStream());
                            crl = (X509CRL) certificateFactory().generateCRL(inStream);
                            revokedCertificate = crl.getRevokedCertificate(serialNumber != null ? serialNumber : certificate.getSerialNumber());
                        } catch (Exception e) {
                            hasError = true;
                            LOGGER.warn("Failed to get the certificate revocation list, try the next one if any", e);
                        } finally {
                            if (inStream != null) {
                                inStream.close();
                            }
                        }
                    }
                    if (hasError && !iterator.hasNext()) {
                        throw new CertificateException("An error has occurred while checking if certificate was revoked");
                    }
                }
                if (revokedCertificate != null) {
                    throw new CertificateException("Certificate has been revoked");
                }
            } catch (IOException ex) {
                throw new CertificateException("Failed to get CRL distribution points");

            }
        } else {
            throw new CertificateException("Failed to find CRL distribution points for the given certificate");
        }
    }

    private void validateCRLSFromCertificate(X509Certificate certificate) throws CertificateException {
        validateCRLSFromCertificate(certificate, null);
    }

    /**
     * Generate RSA Public Key from the ssh-(rsa|dsa) ([A-Za-z0-9/+]+=*) (.*) stored key.
     * @param key String.
     * @return RSAPublicKey
     */
    static RSAPublicKey parsePublicKey(String key) {
        Matcher m = SSH_PUB_KEY.matcher(key);

        if (m.matches()) {
            String alg = m.group(1);
            String encKey = m.group(2);
            //String id = m.group(3);

            if (!"rsa".equalsIgnoreCase(alg)) {
                throw new IllegalArgumentException("Only RSA is currently supported, but algorithm was " + alg);
            }

            return parseSSHPublicKey(encKey);
        }

        return null;
    }

    /**
     * <pre>
     * Each rsa key should start with xxxxssh-rsa and then contains two big integer (modulus & exponent) which are prime number.
     * The modulus & exponent are used to generate the RSA Public Key.
     * <a href="https://en.wikipedia.org/wiki/RSA_(cryptosystem)">See wiki explanations for deeper understanding</a>
     * </pre>
     * @param encKey String
     * @return RSAPublicKey
     */
    private static RSAPublicKey parseSSHPublicKey(String encKey) {
        final byte[] PREFIX = new byte[] {0,0,0,7, 's','s','h','-','r','s','a'};
        ByteArrayInputStream in = new ByteArrayInputStream(Base64.getDecoder().decode(StandardCharsets.UTF_8.encode(encKey)).array());

        byte[] prefix = new byte[11];

        try {
            if (in.read(prefix) != 11 || !Arrays.equals(PREFIX, prefix)) {
                throw new IllegalArgumentException("SSH key prefix not found");
            }

            BigInteger e = new BigInteger(readBigInteger(in));//public exponent
            BigInteger n = new BigInteger(readBigInteger(in));//modulus

            return createPublicKey(n, e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Create an RSA public key from modulus and exponent values
     * @param n modulus
     * @param e public exponent
     * @return
     */
    static RSAPublicKey createPublicKey(BigInteger n, BigInteger e) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
        }
        catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    /**
     * Extract the X509 certificate chain containing the key.
     * This is the Base64 (not Base64URL) encoded version of the DER representation of the certificate.
     * The public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
     * @param x5c The X509 certificate chain containing the key.
     * @return The X509 certificate chain from the x5c value.
     * @throws CertificateException
     */
    static X509Certificate extractCertificateFromX5CHeader(String[] x5c) throws CertificateException {
        return extractCertificate(new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(x5c[0])));
    }

    /**
     * Extract public key from the certificate PEM file.
     * @param pemFile The X509 certificate chain containing the key.
     * @return Public key from the certificate PEM file.
     * @throws FileNotFoundException
     * @throws CertificateException
     */
    static PublicKey extractPublicKeyFromPEMFile(String pemFile) throws IOException, CertificateException {
        String fileContent = new String(Files.readAllBytes(Paths.get(pemFile)), Charset.forName(StandardCharsets.UTF_8.name()));
        // PEM file can contain the entire certificate chain + the private key
        // Remove PRIVATE KEY tags
        fileContent = fileContent.replaceAll(BEGIN_PRIVATE_KEY, "");
        fileContent = fileContent.replaceAll(END_PRIVATE_KEY, "");
        fileContent = fileContent.replaceAll(BEGIN_RSA_PRIVATE_KEY, "");
        fileContent = fileContent.replaceAll(END_RSA_PRIVATE_KEY, "");
        X509Certificate cert = extractCertificate(new ByteArrayInputStream(fileContent.getBytes(StandardCharsets.UTF_8)));
        return cert.getPublicKey();
    }

    /**
     * Extract certificate from input stream (file, string value)
     * @param inputStream
     * @return
     * @throws CertificateException
     */
    static X509Certificate extractCertificate(InputStream inputStream) throws CertificateException {
        X509Certificate cert = (X509Certificate) certificateFactory().generateCertificate(inputStream);
        return cert;
    }

    /**
     * Get certificate factory
     * @return
     * @throws CertificateException
     */
    static CertificateFactory certificateFactory() throws CertificateException {
        return CertificateFactory.getInstance("X.509");
    }

    /**
     * bytes are not in the good order, they are in the big endian format, we reorder them before reading them...
     * Each time you call this method, the buffer position will move, so result are differents...
     * @param in byte array of a public encryption key without 11 "xxxxssh-rsa" first byte.
     * @return BigInteger public exponent on first call, then modulus.
     * @throws IOException
     */
    private static byte[] readBigInteger(ByteArrayInputStream in) throws IOException {
        byte[] b = new byte[4];

        if (in.read(b) != 4) {
            throw new IOException("Expected length data as 4 bytes");
        }

        int l = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];

        b = new byte[l];

        if (in.read(b) != l) {
            throw new IOException("Expected " + l + " key bytes");
        }

        return b;
    }
}
