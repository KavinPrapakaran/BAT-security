package com.cognesis.framework;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * COGNESIS - Cognitive Security Decision Framework.
 * Bootstraps the Spring context that wires the SYNAPSE decision algorithm,
 * Fides trust engine, Mnemonic memory engine and the Cognitive DNS Engine.
 */
@SpringBootApplication
public class CognesisApplication {

    public static void main(String[] args) {
        SpringApplication.run(CognesisApplication.class, args);
    }
}
