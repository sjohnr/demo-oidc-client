/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example;

import java.util.Optional;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.StringUtils;

/**
 * @author Steve Riesenberg
 */
final class ClientRegistrationMapper {
	private ClientRegistrationMapper() {
	}

	static ClientRegistration toObject(Client client) {
		return ClientRegistration.withRegistrationId(client.getClientRegistrationId())
				.clientId(client.getClientId())
				.clientSecret(client.getClientSecret())
				.clientAuthenticationMethod(new ClientAuthenticationMethod(client.getClientAuthenticationMethod()))
				.authorizationGrantType(new AuthorizationGrantType(client.getAuthorizationGrantType()))
				.redirectUri(client.getRedirectUri())
				.scope(StringUtils.commaDelimitedListToSet(client.getScopes()))
				.authorizationUri(withIssuer(client, client.getAuthorizationUri()))
				.tokenUri(withIssuer(client, client.getTokenUri()))
				.userInfoUri(withIssuer(client, client.getUserInfoUri()))
				.userInfoAuthenticationMethod(Optional.ofNullable(client.getUserInfoAuthenticationMethod())
						.map(AuthenticationMethod::new)
						.orElse(null))
				.userNameAttributeName(client.getUserInfoUserNameAttributeName())
				.jwkSetUri(withIssuer(client, client.getJwkSetUri()))
				.issuerUri(client.getIssuerUri())
				.build();
	}

	private static String withIssuer(Client client, String uri) {
		return StringUtils.hasText(uri) ? "%s%s".formatted(client.getIssuerUri(), uri) : null;
	}
}
