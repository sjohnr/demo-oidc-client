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
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManagerBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.JwtBearerGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequestEntityConverter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
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
	@Profile("default")
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

		http
			.authorizeHttpRequests((authorize) -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login((oauth2Login) -> oauth2Login
				.authorizationEndpoint((authorizationEndpoint) -> authorizationEndpoint
					.authorizationRequestResolver(authorizationRequestResolver)
				)
			)
			.oauth2Client((oauth2Client) -> oauth2Client
				.authorizationCodeGrant((authorizationCode) -> authorizationCode
					.accessTokenResponseClient(DefaultAuthorizationCodeTokenResponseClient.builder()
							.requestEntityConverter(OAuth2AuthorizationCodeGrantRequestEntityConverter.builder()
								.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver()))
								.build()
							)
							.restOperations(restTemplate)
							.build()
					)
				)
			);
		// @formatter:on

		return http.build();
	}

	@Bean
	@Profile("default")
	public OAuth2AuthorizedClientManagerBuilder authorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository);
	}

	@Bean
	@Profile("rest")
	public OAuth2AuthorizedClientManagerBuilder restOperationsAuthorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			RestTemplate restTemplate) {

		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository)
				.restOperations(restTemplate);
	}

	@Bean
	@Profile("authorization_code")
	public OAuth2AuthorizedClientManagerBuilder authorizationCodeAuthorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		// @formatter:off
		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers(OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken()
				);
		// @formatter:on
	}

	@Bean
	@Profile("client_credentials")
	public OAuth2AuthorizedClientManagerBuilder clientCredentialsAuthorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		// @formatter:off
		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers(OAuth2AuthorizedClientProviderBuilder.builder()
						.clientCredentials((clientCredentials) -> clientCredentials
								.accessTokenResponseClient(DefaultClientCredentialsTokenResponseClient.builder()
										.requestEntityConverter(OAuth2ClientCredentialsGrantRequestEntityConverter.builder()
												.defaultParameters((parameters) -> parameters.set("audience", "xyz_value"))
												.build()
										)
										.build()
								)
								.build()
						)
				);
		// @formatter:on
	}

	@Bean
	@Profile("private_key_jwt")
	public OAuth2AuthorizedClientManagerBuilder jwtClientAuthenticationAuthorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		// @formatter:off
		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers(OAuth2AuthorizedClientProviderBuilder.builder()
						.clientCredentials((clientCredentials) -> clientCredentials
								.accessTokenResponseClient(DefaultClientCredentialsTokenResponseClient.builder()
										.requestEntityConverter(OAuth2ClientCredentialsGrantRequestEntityConverter.builder()
												.addParametersConverter(new NimbusJwtClientAuthenticationParametersConverter<>(jwkResolver()))
												.build()
										)
										.build()
								)
								.build()
						)
				);
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
	public OAuth2AuthorizedClientManagerBuilder jwtAuthorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			RestTemplate restTemplate) {

		// @formatter:off
		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository)
				.restOperations(restTemplate)
				.providers(OAuth2AuthorizedClientProviderBuilder.builder()
						.provider(JwtBearerOAuth2AuthorizedClientProvider.builder()
								.accessTokenResponseClient(DefaultJwtBearerTokenResponseClient.builder()
										.restOperations(restTemplate)
										.build()
								)
								.build()
						)
				);
		// @formatter:on
	}

	@Bean
	@Profile("password")
	public OAuth2AuthorizedClientManagerBuilder passwordAuthorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository)
				.contextAttributesMapper(contextAttributesMapper());
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
	public OAuth2AuthorizedClientManagerBuilder kitchenSinkAuthorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository,
			RestTemplate restTemplate) {

		// @formatter:off
		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository)
				.providers(OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken((refreshToken) -> refreshToken
								.accessTokenResponseClient(DefaultRefreshTokenTokenResponseClient.builder()
										.requestEntityConverter(OAuth2RefreshTokenGrantRequestEntityConverter.builder()
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
								.accessTokenResponseClient(DefaultClientCredentialsTokenResponseClient.builder()
										.requestEntityConverter(OAuth2ClientCredentialsGrantRequestEntityConverter.builder()
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
						.password((password) -> password
								.accessTokenResponseClient(DefaultPasswordTokenResponseClient.builder()
										.requestEntityConverter(OAuth2PasswordGrantRequestEntityConverter.builder()
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
								.accessTokenResponseClient(DefaultJwtBearerTokenResponseClient.builder()
										.requestEntityConverter(JwtBearerGrantRequestEntityConverter.builder()
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
				.authorizationFailureHandler((exception, principal, attributes) -> {/* ... */});
		// @formatter:on
	}

	@Bean
	public RestTemplate restTemplate() {
		// @formatter:off
		var restTemplate = new RestTemplate(List.of(
				new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
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
