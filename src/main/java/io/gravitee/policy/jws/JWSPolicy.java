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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.common.http.MediaType;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.stream.TransformableRequestStreamBuilder;
import io.gravitee.gateway.api.stream.ReadWriteStream;
import io.gravitee.gateway.api.stream.exception.TransformationException;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequestContent;
import io.gravitee.policy.jws.utils.JsonUtils;
import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.DefaultClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Function;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
*/
public class JWSPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(JWSPolicy.class);

    @OnRequestContent
    public ReadWriteStream onRequestContent(Request request, PolicyChain policyChain) {
        return TransformableRequestStreamBuilder
                .on(request)
                .contentType(MediaType.APPLICATION_JSON)
                .transform(map(policyChain))
                .build();
    }

    Function<Buffer, Buffer> map(PolicyChain policyChain) {
        return input -> {
            try {
                DefaultClaims jwtClaims = validateJsonWebToken(input.toString());
                return Buffer.buffer(JsonUtils.writeValueAsString(jwtClaims));
            } catch (UnsupportedJwtException | ExpiredJwtException | MalformedJwtException | SignatureException | IllegalArgumentException ex) {
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
    private DefaultClaims validateJsonWebToken(String jwt) {
        // v0 untrusted jwt, keep expired jwt exception
        int i = jwt.lastIndexOf('.');
        String untrustedJwtString = jwt.substring(0, i+1);
        Jwt<Header,Claims> untrusted = Jwts.parser().parseClaimsJwt(untrustedJwtString);

        return ((DefaultClaims) untrusted.getBody());
    }
}
