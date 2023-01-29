package org.sid.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MockRestAPI {

    @GetMapping("/dataTest")
    public Map<String,Object> getMock(){
        return Map.of("message","Data-test");
    }


}
