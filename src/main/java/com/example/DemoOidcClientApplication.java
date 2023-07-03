package com.example;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.JwtBearerOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.DefaultMapOAuth2AccessTokenResponseConverter;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
public class DemoOidcClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoOidcClientApplication.class, args);
	}

	@Bean
	@Profile({ "default", "authorization_code", "client_credentials", "private_key_jwt", "jwt_bearer", "password" })
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login(Customizer.withDefaults())
			.oauth2Client(Customizer.withDefaults());
		// @formatter:on

		return http.build();
	}

	@Bean
	@Profile("rest")
	public SecurityFilterChain restSecurityFilterChain(HttpSecurity http,
			RestTemplate restTemplate) throws Exception {

		// @formatter:off
		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient =
			DefaultAuthorizationCodeTokenResponseClient.builder()
				.restOperations(restTemplate)
				.build();

		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login((oauth2Login) -> oauth2Login
				.tokenEndpoint((tokenEndpoint) -> tokenEndpoint
					.accessTokenResponseClient(accessTokenResponseClient)
				)
			)
			.oauth2Client((oauth2Client) -> oauth2Client
				.authorizationCodeGrant((authorizationCode) -> authorizationCode
					.accessTokenResponseClient(accessTokenResponseClient)
				)
			);
		// @formatter:on

		return http.build();
	}

	@Bean
	@Profile("default")
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository).build();
	}

	@Bean
	@Profile("rest")
	public OAuth2AuthorizedClientManager restOperationsAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			RestTemplate restTemplate) {

		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository)
				.restOperations(restTemplate)
				.build();
	}

	@Bean
	@Profile("authorization_code")
	public OAuth2AuthorizedClientManager authorizationCodeAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		// @formatter:off
		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers((providers) -> providers
						.authorizationCode()
						.refreshToken()
				)
				.build();
		// @formatter:on
	}

	@Bean
	@Profile("client_credentials")
	public OAuth2AuthorizedClientManager clientCredentialsAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		// @formatter:off
		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers((providers) -> providers
						.clientCredentials((clientCredentials) -> clientCredentials
								.accessTokenResponseClient((client) -> client
										.requestEntityConverter((converter) -> converter
												.defaultParameters((parameters) -> parameters.set("audience", "xyz_value"))
										)
								)
						)
				)
				.build();
		// @formatter:on
	}

	@Bean
	@Profile("private_key_jwt")
	public OAuth2AuthorizedClientManager jwtClientAuthenticationAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		// @formatter:off
		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers((providers) -> providers
						.clientCredentials((clientCredentials) -> clientCredentials
								.accessTokenResponseClient((client) -> client
										.requestEntityConverter((converter) -> converter
												.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver()))
										)
								)
						)
				)
				.build();
		// @formatter:on
	}

	/**
	 * @see <a href="https://docs.spring.io/spring-security/reference/servlet/oauth2/client/client-authentication.html#_authenticate_using_private_key_jwt">
	 *     private_key_jwt</a>
	 */
	private static Function<ClientRegistration, JWK> jwkResolver() {
		KeyPair keyPair = generateRsaKey();
		return (clientRegistration) -> {
			if (clientRegistration.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
				RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
				RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
				return new RSAKey.Builder(publicKey).privateKey(privateKey)
						.keyID(UUID.randomUUID().toString())
						.build();
			}
			return null;
		};
	}

	private static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	@Bean
	@Profile("jwt_bearer")
	public OAuth2AuthorizedClientManager jwtAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			RestTemplate restTemplate) {

		// @formatter:off
		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository)
				.restOperations(restTemplate)
				.providers((providers) -> providers
						.provider(JwtBearerOAuth2AuthorizedClientProvider.builder()
								.accessTokenResponseClient((client) -> client
										.restOperations(restTemplate)
								)
								.build()
						)
				)
				.build();
		// @formatter:on
	}

	@Bean
	@Profile("password")
	public OAuth2AuthorizedClientManager passwordAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository)
				.contextAttributesMapper(contextAttributesMapper())
				.build();
	}

	/**
	 * @see <a href="https://docs.spring.io/spring-security/reference/servlet/oauth2/client/core.html#oauth2Client-authorized-manager-provider">
	 *     OAuth2AuthorizedClientManager</a>.
	 */
	private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {
		return authorizeRequest -> {
			Map<String, Object> contextAttributes = Collections.emptyMap();
			HttpServletRequest request = authorizeRequest.getAttribute(HttpServletRequest.class.getName());
			Assert.notNull(request, "request cannot be null");
			String username = request.getParameter(OAuth2ParameterNames.USERNAME);
			String password = request.getParameter(OAuth2ParameterNames.PASSWORD);
			if (StringUtils.hasText(username) && StringUtils.hasText(password)) {
				contextAttributes = Map.of(
						OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username,
						OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password
				);
			}
			return contextAttributes;
		};
	}

	@Bean
	@Profile("kitchen_sink")
	public SecurityFilterChain securityFilterChain(HttpSecurity http,
			ClientRegistrationRepository clientRegistrationRepository,
			RestTemplate restTemplate) throws Exception {

		// @formatter:off
		DefaultOAuth2AuthorizationRequestResolver authorizationRequestResolver =
				new DefaultOAuth2AuthorizationRequestResolver(
						clientRegistrationRepository, "/oauth2/authorize");
		authorizationRequestResolver.setAuthorizationRequestCustomizer(
				OAuth2AuthorizationRequestCustomizers.withPkce());

		OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient =
			DefaultAuthorizationCodeTokenResponseClient.builder()
				.requestEntityConverter((converter) -> converter
					.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver()))
				)
				.restOperations(restTemplate)
				.build();

		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login((oauth2Login) -> oauth2Login
				.authorizationEndpoint((authorizationEndpoint) -> authorizationEndpoint
					.authorizationRequestResolver(authorizationRequestResolver)
				)
				.tokenEndpoint((tokenEndpoint) -> tokenEndpoint
					.accessTokenResponseClient(accessTokenResponseClient)
				)
			)
			.oauth2Client((oauth2Client) -> oauth2Client
				.authorizationCodeGrant((authorizationCode) -> authorizationCode
					.accessTokenResponseClient(accessTokenResponseClient)
				)
			);
		// @formatter:on

		return http.build();
	}

	@Bean
	@Profile("kitchen_sink")
	public OAuth2AuthorizedClientManager kitchenSinkAuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			RestTemplate restTemplate) {

		// @formatter:off
		return OAuth2AuthorizedClientManager.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers((providers) -> providers
						.authorizationCode()
						.refreshToken((refreshToken) -> refreshToken
								.accessTokenResponseClient((client) -> client
										.requestEntityConverter((converter) -> converter
												.headersConverter((request) -> new HttpHeaders()/* ... */)
												.defaultHeaders((headers) -> headers.setAccept(List.of(MediaType.APPLICATION_JSON)))
												.addHeadersConverter((request) -> new HttpHeaders()/* ... */)
												.parametersConverter((request) -> new LinkedMultiValueMap<>()/* ... */)
												.defaultParameters((parameters) -> parameters.set("audience", "xyz_value"))
												.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver()))
												.build()
										)
										.restOperations(restTemplate)
										.build()
								)
								.clock(Clock.systemUTC())
								.clockSkew(Duration.ofMinutes(1))
								.build()
						)
						.clientCredentials((clientCredentials) -> clientCredentials
								.accessTokenResponseClient((client) -> client
										.requestEntityConverter((converter) -> converter
												.headersConverter((request) -> new HttpHeaders()/* ... */)
												.defaultHeaders((headers) -> headers.setAccept(List.of(MediaType.APPLICATION_JSON)))
												.addHeadersConverter((request) -> new HttpHeaders()/* ... */)
												.parametersConverter((request) -> new LinkedMultiValueMap<>()/* ... */)
												.defaultParameters((parameters) -> parameters.set("audience", "xyz_value"))
												.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver()))
												.build()
										)
										.restOperations(restTemplate)
										.build()
								)
								.clock(Clock.systemUTC())
								.clockSkew(Duration.ofMinutes(1))
								.build()
						)
						.provider(JwtBearerOAuth2AuthorizedClientProvider.builder()
								.accessTokenResponseClient((client) -> client
										.requestEntityConverter((converter) -> converter
												.headersConverter((request) -> new HttpHeaders()/* ... */)
												.defaultHeaders((headers) -> headers.setAccept(List.of(MediaType.APPLICATION_JSON)))
												.addHeadersConverter((request) -> new HttpHeaders()/* ... */)
												.parametersConverter((request) -> new LinkedMultiValueMap<>()/* ... */)
												.defaultParameters((parameters) -> parameters.set("audience", "xyz_value"))
												.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver()))
												.build()
										)
										.restOperations(restTemplate)
										.build()
								)
								.clock(Clock.systemUTC())
								.clockSkew(Duration.ofMinutes(1))
								.build()
						)
				)
				.contextAttributesMapper(contextAttributesMapper())
				.authorizationSuccessHandler((client, principal, attributes) -> {/* ... */})
				.authorizationFailureHandler((exception, principal, attributes) -> {/* ... */})
				.build();
		// @formatter:on
	}

	@Bean
	public RestTemplate restTemplate() {
		var accessTokenResponseMessageConverter = new OAuth2AccessTokenResponseHttpMessageConverter();
		var accessTokenResponseConverterDelegate = new DefaultMapOAuth2AccessTokenResponseConverter();
		accessTokenResponseMessageConverter.setAccessTokenResponseConverter((map) -> {
			var accessTokenResponse = accessTokenResponseConverterDelegate.convert(map);
			if (map.containsKey("scp")) {
				System.out.println("Handling custom scp parameter...");
				return OAuth2AccessTokenResponse.withResponse(accessTokenResponse)
						.scopes(StringUtils.commaDelimitedListToSet(map.get("scp").toString()))
						.build();
			}
			return accessTokenResponse;
		});

		// @formatter:off
		var restTemplate = new RestTemplate(List.of(
				new FormHttpMessageConverter(),
				accessTokenResponseMessageConverter));
		// @formatter:on
		// ...

		return restTemplate;
	}

	@Bean
	public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
		var oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		return WebClient.builder().apply(oauth2.oauth2Configuration()).build();
	}

}
