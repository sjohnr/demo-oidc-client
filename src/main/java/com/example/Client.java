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

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

/**
 * @author Steve Riesenberg
 */
@Table("client_registration")
public class Client {
	@Id
	@Column("client_registration_id")
	private String clientRegistrationId;

	@Column("client_id")
	private String clientId;

	@Column("client_secret")
	private String clientSecret;

	@Column("client_authentication_method")
	private String clientAuthenticationMethod;

	@Column("authorization_grant_type")
	private String authorizationGrantType;

	@Column("redirect_uri")
	private String redirectUri;

	@Column("scopes")
	private String scopes;

	@Column("authorization_uri")
	private String authorizationUri;

	@Column("token_uri")
	private String tokenUri;

	@Column("user_info_uri")
	private String userInfoUri;

	@Column("user_info_authentication_method")
	private String userInfoAuthenticationMethod;

	@Column("user_info_user_name_attribute_name")
	private String userInfoUserNameAttributeName;

	@Column("jwk_set_uri")
	private String jwkSetUri;

	@Column("issuer_uri")
	private String issuerUri;

	public String getClientRegistrationId() {
		return this.clientRegistrationId;
	}

	public Client clientRegistrationId(String clientRegistrationId) {
		this.clientRegistrationId = clientRegistrationId;
		return this;
	}

	public String getClientId() {
		return this.clientId;
	}

	public Client clientId(String clientId) {
		this.clientId = clientId;
		return this;
	}

	public String getClientSecret() {
		return this.clientSecret;
	}

	public Client clientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
		return this;
	}

	public String getClientAuthenticationMethod() {
		return this.clientAuthenticationMethod;
	}

	public Client clientAuthenticationMethod(String clientAuthenticationMethod) {
		this.clientAuthenticationMethod = clientAuthenticationMethod;
		return this;
	}

	public String getAuthorizationGrantType() {
		return this.authorizationGrantType;
	}

	public Client authorizationGrantType(String authorizationGrantType) {
		this.authorizationGrantType = authorizationGrantType;
		return this;
	}

	public String getRedirectUri() {
		return this.redirectUri;
	}

	public Client redirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
		return this;
	}

	public String getScopes() {
		return this.scopes;
	}

	public Client scopes(String scopes) {
		this.scopes = scopes;
		return this;
	}

	public String getAuthorizationUri() {
		return this.authorizationUri;
	}

	public Client authorizationUri(String authorizationUri) {
		this.authorizationUri = authorizationUri;
		return this;
	}

	public String getTokenUri() {
		return this.tokenUri;
	}

	public Client tokenUri(String tokenUri) {
		this.tokenUri = tokenUri;
		return this;
	}

	public String getUserInfoUri() {
		return this.userInfoUri;
	}

	public Client userInfoUri(String userInfoUri) {
		this.userInfoUri = userInfoUri;
		return this;
	}

	public String getUserInfoAuthenticationMethod() {
		return this.userInfoAuthenticationMethod;
	}

	public Client userInfoAuthenticationMethod(String userInfoAuthenticationMethod) {
		this.userInfoAuthenticationMethod = userInfoAuthenticationMethod;
		return this;
	}

	public String getUserInfoUserNameAttributeName() {
		return this.userInfoUserNameAttributeName;
	}

	public Client userInfoUserNameAttributeName(String userInfoUserNameAttributeName) {
		this.userInfoUserNameAttributeName = userInfoUserNameAttributeName;
		return this;
	}

	public String getJwkSetUri() {
		return this.jwkSetUri;
	}

	public Client jwkSetUri(String jwkSetUri) {
		this.jwkSetUri = jwkSetUri;
		return this;
	}

	public String getIssuerUri() {
		return this.issuerUri;
	}

	public Client issuerUri(String issuerUri) {
		this.issuerUri = issuerUri;
		return this;
	}

	public static Builder builder() {
		return new Builder(new Client());
	}

	public static final class Builder {
		private Client client;

		private Builder(Client client) {
			this.client = client;
		}

		public Builder clientRegistrationId(String clientRegistrationId) {
			this.client.clientRegistrationId = clientRegistrationId;
			return this;
		}

		public Builder clientId(String clientId) {
			this.client.clientId = clientId;
			return this;
		}

		public Builder clientSecret(String clientSecret) {
			this.client.clientSecret = clientSecret;
			return this;
		}

		public Builder clientAuthenticationMethod(String clientAuthenticationMethod) {
			this.client.clientAuthenticationMethod = clientAuthenticationMethod;
			return this;
		}

		public Builder authorizationGrantType(String authorizationGrantType) {
			this.client.authorizationGrantType = authorizationGrantType;
			return this;
		}

		public Builder redirectUri(String redirectUri) {
			this.client.redirectUri = redirectUri;
			return this;
		}

		public Builder scopes(String scopes) {
			this.client.scopes = scopes;
			return this;
		}

		public Builder authorizationUri(String authorizationUri) {
			this.client.authorizationUri = authorizationUri;
			return this;
		}

		public Builder tokenUri(String tokenUri) {
			this.client.tokenUri = tokenUri;
			return this;
		}

		public Builder userInfoUri(String userInfoUri) {
			this.client.userInfoUri = userInfoUri;
			return this;
		}

		public Builder userInfoAuthenticationMethod(String userInfoAuthenticationMethod) {
			this.client.userInfoAuthenticationMethod = userInfoAuthenticationMethod;
			return this;
		}

		public Builder userInfoUserNameAttributeName(String userInfoUserNameAttributeName) {
			this.client.userInfoUserNameAttributeName = userInfoUserNameAttributeName;
			return this;
		}

		public Builder jwkSetUri(String jwkSetUri) {
			this.client.jwkSetUri = jwkSetUri;
			return this;
		}

		public Builder issuerUri(String issuerUri) {
			this.client.issuerUri = issuerUri;
			return this;
		}
	}
}
