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

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

/**
 * @author Steve Riesenberg
 */
@RestController
public class HelloController {
	private final WebClient webClient;

	public HelloController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping("/")
	public String hello(Authentication authentication) {
		return "Hello " + authentication.getName();
	}

	@GetMapping("/users")
	public ResponseEntity<?> users() {
		return this.webClient.get()
				.uri("http://localhost:8090/users")
				.attributes(clientRegistrationId("spring"))
				.retrieve()
				.toEntity(Object.class)
				.block();
	}
}
