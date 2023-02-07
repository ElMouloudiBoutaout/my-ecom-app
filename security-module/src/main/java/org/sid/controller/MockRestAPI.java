package org.sid.controller;

import org.sid.service.MockService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MockRestAPI {


    @GetMapping("/testUser")
    public Map<String, Object> checkUser(Authentication authentication) {

        return Map.of(
                "message", "check-User",
                "username", authentication.getName(),
                "Authorities", authentication.getAuthorities()
        );

    }

    @GetMapping("/dataTest")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public Map<String, Object> getMock(Authentication authentication) {

        return Map.of(
                "message", "data-Test",
                "username", authentication.getName(),
                "Authorities", authentication.getAuthorities()
        );


    }

    @GetMapping("/saveData")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public Map<String, Object> saveMockData(Authentication authentication) {

        return Map.of(
                "message", "Data saved",
                "username", authentication.getName(),
                "Authorities", authentication.getAuthorities()
        );


    }


}
