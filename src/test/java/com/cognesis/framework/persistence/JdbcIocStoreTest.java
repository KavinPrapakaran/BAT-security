package com.cognesis.framework.persistence;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * IOC persistence must survive restarts: a fresh store instance on the same
 * database still sees flags written earlier. This is the "the framework
 * remembers its threat intel" invariant.
 */
class JdbcIocStoreTest {

    private DriverManagerDataSource dataSource;

    @BeforeEach
    void setUp() {
        dataSource = new DriverManagerDataSource();
        dataSource.setUrl("jdbc:h2:mem:iocstore;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        dataSource.setUsername("sa");
        dataSource.setPassword("");
        dataSource.setDriverClassName("org.h2.Driver");
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource("db/schema-h2.sql"));
        populator.execute(dataSource);
    }

    private JdbcIocStore store() {
        return new JdbcIocStore(new NamedParameterJdbcTemplate(new JdbcTemplate(dataSource)));
    }

    @Test
    void flagsPersistAcrossStoreInstances() {
        JdbcIocStore first = store();
        first.flag("evil.example");
        first.flag("evil.example");

        JdbcIocStore second = store();

        assertEquals(2, second.flagCount("evil.example"), "flag count must survive a new store instance");
        assertEquals(1, second.total());
        assertTrue(second.firstSeen("evil.example").isPresent());
    }

    @Test
    void unknownDomainHasZeroFlags() {
        JdbcIocStore store = store();
        assertEquals(0, store.flagCount("never-flagged.example"));
        assertFalse(store.firstSeen("never-flagged.example").isPresent());
    }

    @Test
    void firstSeenIsStableAcrossReflags() {
        JdbcIocStore store = store();
        store.flag("repeat.example");
        Instant first = store.firstSeen("repeat.example").orElseThrow();
        store.flag("repeat.example");
        assertEquals(first, store.firstSeen("repeat.example").orElseThrow(),
                "first_seen must not move on subsequent flags");
    }
}
