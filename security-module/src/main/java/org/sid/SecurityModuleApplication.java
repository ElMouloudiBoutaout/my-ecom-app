package org.sid;

import org.sid.configuration.RSAKeysConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RSAKeysConfiguration.class)
public class SecurityModuleApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityModuleApplication.class, args);
	}

}
