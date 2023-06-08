package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManagerBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
public class DemoOidcClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoOidcClientApplication.class, args);
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository(ClientRepository clientRepository) {
		return new JdbcClientRegistrationRepository(clientRepository);
	}

	@Bean
	public OAuth2AuthorizedClientService authorizedClientService(
			JdbcOperations jdbcOperations,
			ClientRegistrationRepository clientRegistrationRepository) {
		return new JdbcOAuth2AuthorizedClientService(jdbcOperations, clientRegistrationRepository);
	}

	@Bean
	public OAuth2AuthorizedClientManagerBuilder authorizedClientManagerBuilder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {

		return OAuth2AuthorizedClientManagerBuilder.builder(clientRegistrationRepository, authorizedClientRepository);
	}

	@Bean
	public WebClient webClient(OAuth2AuthorizedClientManager authorizedClientManager) {
		var oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(authorizedClientManager);
		return WebClient.builder().apply(oauth2.oauth2Configuration()).build();
	}

}
