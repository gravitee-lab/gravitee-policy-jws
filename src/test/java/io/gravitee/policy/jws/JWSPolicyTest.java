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

import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.policy.api.PolicyChain;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.runners.MockitoJUnitRunner;
import org.skyscreamer.jsonassert.JSONAssert;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.UUID;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Titouan COMPIEGNE (titouan.compiegne at graviteesource.com)
 * @author GraviteeSource Team
 */
@RunWith(MockitoJUnitRunner.class)
public class JWSPolicyTest {

    private JWSPolicy jwsPolicy;

    @Mock
    private PolicyChain policyChain;

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
        jwsPolicy = new JWSPolicy();
    }

    @Test
    public void shouldTransformInput() throws Exception {
        String input = loadResource("/io/gravitee/policy/jws/jws.json");
        String expected = loadResource("/io/gravitee/policy/jws/expected-jws-payload.json");

        // Prepare context
        Buffer ret = jwsPolicy.map(policyChain).apply(Buffer.buffer(input));
        Assert.assertNotNull(ret);

        JSONAssert.assertEquals(expected, ret.toString(), false);
    }

    @Test
    public void shouldTransformInput_malformedJWS() throws Exception {
        String input = loadResource("/io/gravitee/policy/jws/malformed-jws.json");

        // Prepare context
        Buffer ret = jwsPolicy.map(policyChain).apply(Buffer.buffer(input));
        verify(policyChain, times(1)).streamFailWith(any());
        Assert.assertNull(ret);
    }

    @Test
    public void shouldTransformInput_expiredToken() {
        byte[] key = MacProvider.generateKey().getEncoded();
        String id = UUID.randomUUID().toString();

        String input = Jwts.builder().setId(id)
                .setAudience("an audience")
                .setExpiration(new GregorianCalendar(2014, Calendar.JANUARY, 1).getTime())
                .signWith(SignatureAlgorithm.HS256, key)
                .compact();

        Buffer ret = jwsPolicy.map(policyChain).apply(Buffer.buffer(input));
        verify(policyChain, times(1)).streamFailWith(any());
        Assert.assertNull(ret);

    }

    private String loadResource(String resource) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(resource);
        StringWriter sw = new StringWriter();
        IOUtils.copy(is, sw, "UTF-8");
        return sw.toString();
    }
}
