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
package io.gravitee.policy.jws.utils;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
public interface JwsHeader {

    /** JWS {@code Algorithm} header parameter name: <code>"alg"</code> */
    String ALGORITHM = "alg";

    /** JWS {@code JWT Set URL} header parameter name: <code>"jku"</code> */
    String JWK_SET_URL = "jku";

    /** JWS {@code JSON Web Key} header parameter name: <code>"jwk"</code> */
    String JSON_WEB_KEY = "jwk";

    /** JWS {@code Key ID} header parameter name: <code>"kid"</code> */
    String KEY_ID = "kid";

    /** JWS {@code X.509 URL} header parameter name: <code>"x5u"</code> */
    String X509_URL = "x5u";

    /** JWS {@code X.509 Certificate Chain} header parameter name: <code>"x5c"</code> */
    String X509_CERT_CHAIN = "x5c";

    /** JWS {@code X.509 Certificate SHA-1 Thumbprint} header parameter name: <code>"x5t"</code> */
    String X509_CERT_SHA1_THUMBPRINT = "x5t";

    /** JWS {@code X.509 Certificate SHA-256 Thumbprint} header parameter name: <code>"x5t#S256"</code> */
    String X509_CERT_SHA256_THUMBPRINT = "x5t#S256";

    /** JWS {@code Critical} header parameter name: <code>"crit"</code> */
    String CRITICAL = "crit";

    /** JWS {@code Type} header parameter name: <code>"typ"</code> */
    String TYPE = "typ";

    /** JWS {@code Content Type} header parameter name: <code>"cty"</code> */
    String CONTENT_TYPE = "cty";

}
