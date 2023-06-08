package com.example;

import java.util.List;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.client.JwtBearerOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultJwtBearerTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

@EnableWebFluxSecurity
@SpringBootApplication
public class DemoOidcClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoOidcClientApplication.class, args);
	}

	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		RestOperations restOperations = new RestTemplate(List.of(
				new FormHttpMessageConverter(),
				new OAuth2AccessTokenResponseHttpMessageConverter()));
		// ..

		DefaultRefreshTokenTokenResponseClient refreshTokenAccessTokenResponseClient =
				new DefaultRefreshTokenTokenResponseClient();
		refreshTokenAccessTokenResponseClient.setRestOperations(restOperations);

		DefaultClientCredentialsTokenResponseClient clientCredentialsAccessTokenResponseClient =
				new DefaultClientCredentialsTokenResponseClient();
		clientCredentialsAccessTokenResponseClient.setRestOperations(restOperations);

		DefaultPasswordTokenResponseClient passwordAccessTokenResponseClient =
				new DefaultPasswordTokenResponseClient();
		passwordAccessTokenResponseClient.setRestOperations(restOperations);

		DefaultJwtBearerTokenResponseClient jwtBearerAccessTokenResponseClient =
				new DefaultJwtBearerTokenResponseClient();
		jwtBearerAccessTokenResponseClient.setRestOperations(restOperations);

		JwtBearerOAuth2AuthorizedClientProvider jwtBearerAuthorizedClientProvider =
				new JwtBearerOAuth2AuthorizedClientProvider();
		jwtBearerAuthorizedClientProvider.setAccessTokenResponseClient(jwtBearerAccessTokenResponseClient);

		OAuth2AuthorizedClientProvider authorizedClientProvider =
				OAuth2AuthorizedClientProviderBuilder.builder()
						.authorizationCode()
						.refreshToken(c -> c.accessTokenResponseClient(refreshTokenAccessTokenResponseClient))
						.clientCredentials(c -> c.accessTokenResponseClient(clientCredentialsAccessTokenResponseClient))
						.password(c -> c.accessTokenResponseClient(passwordAccessTokenResponseClient))
						.provider(jwtBearerAuthorizedClientProvider)
						.build();

		DefaultOAuth2AuthorizedClientManager authorizedClientManager =
				new DefaultOAuth2AuthorizedClientManager(
						clientRegistrationRepository, authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

		return authorizedClientManager;
	}

	@Bean
	public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
		ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
				new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);

		return WebClient.builder()
				.apply(oauth2.oauth2Configuration())
				.build();
	}

}
