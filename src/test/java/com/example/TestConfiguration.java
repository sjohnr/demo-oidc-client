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

import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.ext.ScriptUtils;
import org.testcontainers.jdbc.JdbcDatabaseDelegate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

/**
 * @author Steve Riesenberg
 */
@Configuration
class TestConfiguration {

	@Autowired
	void init(MySQLContainer<?> mysql) {
		var delegate = new JdbcDatabaseDelegate(mysql, "");
		ScriptUtils.runInitScript(delegate, "org/springframework/security/oauth2/client/oauth2-client-schema.sql");
		ScriptUtils.runInitScript(delegate, "org/springframework/session/jdbc/schema-mysql.sql");
		ScriptUtils.runInitScript(delegate, "client-registration-schema.sql");
		ScriptUtils.runInitScript(delegate, "init-client-registration-schema.sql");
	}

}
