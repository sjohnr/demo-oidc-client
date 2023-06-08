package com.example;

import org.testcontainers.containers.MySQLContainer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;

@TestConfiguration(proxyBeanMethods = false)
class TestDemoOidcClientApplication {

	@Bean
	@ServiceConnection
	MySQLContainer<?> mysqlContainer() {
		return new MySQLContainer<>("mysql:latest");
	}

	public static void main(String[] args) {
		SpringApplication.from(DemoOidcClientApplication::main).with(TestDemoOidcClientApplication.class).run(args);
	}

}
