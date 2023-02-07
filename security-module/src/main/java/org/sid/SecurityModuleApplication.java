package org.sid;

import org.sid.configuration.RSAKeysConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

import static org.springframework.security.core.authority.AuthorityUtils.createAuthorityList;

@SpringBootApplication
@EnableConfigurationProperties(RSAKeysConfiguration.class)
public class SecurityModuleApplication {

	public static void main(String[] args) {

		ApplicationContext ctx = SpringApplication.run(SecurityModuleApplication.class, args);
		RoleHierarchy roleHierarchy = ctx.getBean(RoleHierarchy.class);

		for (String role : List.of("ROLE_ADMIN", "ROLE_USER")) {
			System.out.printf("Role: %s implies: %s%n", role,
					roleHierarchy.getReachableGrantedAuthorities(createAuthorityList(role)));

		}
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}


	@Bean
	public UserDetailsChecker userDetailsChecker() {
		return ((var userDetails) -> {
			if (!userDetails.isAccountNonLocked()) {
				throw new UsernameNotFoundException("The account is Locked check with your Admin");
			}
		});

	}
}
