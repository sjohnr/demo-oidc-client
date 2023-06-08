package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;

@EnableWebFluxSecurity
@SpringBootApplication
public class DemoOidcClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoOidcClientApplication.class, args);
	}

}
