package com.mayis.spring_security_jwt_lab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SpringSecurityJwtLabApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtLabApplication.class, args);
	}

}
