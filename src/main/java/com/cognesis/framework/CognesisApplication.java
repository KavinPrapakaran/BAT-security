package com.cognesis.framework;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * BAT security - engineering-first, evidence-driven.
 * Bootstraps the Spring context that wires the ACTG trust graph, SYNAPSE
 * decision algorithm, Fides trust engine, Mnemonic memory engine, LORE
 * decision learning and the DNS Intelligence Engine.
 */
@SpringBootApplication
@EnableScheduling
public class CognesisApplication {

    public static void main(String[] args) {
        SpringApplication.run(CognesisApplication.class, args);
    }
}
