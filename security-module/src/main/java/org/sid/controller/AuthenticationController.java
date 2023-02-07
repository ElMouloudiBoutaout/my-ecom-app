package org.sid.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Logger;
import java.util.stream.Collectors;

@RestController
public class AuthenticationController {

    public static Logger logger = Logger.getLogger(AuthenticationController.class.getName());

    @Autowired
    JwtEncoder jwtEncoder;

    @Autowired
    JwtDecoder jwtDecoder;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping("/token")
    public Map<String, String> jwtToken(String username, String password) {

        logger.info("The username is " + username + " and password " + password);

        Objects.requireNonNull(username);
        Objects.requireNonNull(password);

        Instant instant = Instant.now();

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        String scope = authentication.getAuthorities()
                .stream().map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .subject(authentication.getName())
                .issuedAt(instant)
                .expiresAt(instant.plus(10, ChronoUnit.MINUTES))
                .claim("scope", scope)
                .issuer("security-service")
                .build();

        String jwtAccessToken = jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();

        return Map.of("accessToken",jwtAccessToken);
    }


}
