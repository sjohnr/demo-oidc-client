CREATE TABLE client_registration (
  client_registration_id varchar(100) NOT NULL,
  client_id varchar(200) NOT NULL,
  client_secret varchar(200) NOT NULL,
  client_authentication_method varchar(200) NOT NULL,
  authorization_grant_type varchar(200) NOT NULL,
  redirect_uri varchar(200) DEFAULT NULL,
  scopes varchar(200) DEFAULT NULL,
  authorization_uri varchar(200) DEFAULT NULL,
  token_uri varchar(200) DEFAULT NULL,
  user_info_uri varchar(200) DEFAULT NULL,
  user_info_authentication_method varchar(200) DEFAULT NULL,
  user_info_user_name_attribute_name varchar(200) DEFAULT NULL,
  jwk_set_uri varchar(200) DEFAULT NULL,
  issuer_uri varchar(200) DEFAULT NULL,
  created_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
  PRIMARY KEY (client_registration_id)
);
