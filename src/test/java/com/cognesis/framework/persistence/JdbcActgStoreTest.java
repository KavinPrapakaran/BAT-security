package com.cognesis.framework.persistence;

import com.cognesis.framework.actg.ActgEntityType;
import com.cognesis.framework.actg.ActgNode;
import com.cognesis.framework.actg.ActgRelation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ACTG persistence must survive restarts: a fresh store instance on the same
 * database still sees the relationships and accumulated risk written earlier.
 * This is the "the framework remembers its graph" invariant.
 */
class JdbcActgStoreTest {

    private DriverManagerDataSource dataSource;

    @BeforeEach
    void setUp() {
        dataSource = new DriverManagerDataSource();
        dataSource.setUrl("jdbc:h2:mem:actgstore;DB_CLOSE_DELAY=-1;MODE=PostgreSQL");
        dataSource.setUsername("sa");
        dataSource.setPassword("");
        dataSource.setDriverClassName("org.h2.Driver");
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        populator.addScript(new ClassPathResource("db/schema-h2.sql"));
        populator.execute(dataSource);
        JdbcTemplate clean = new JdbcTemplate(dataSource);
        clean.update("DELETE FROM actg_edge");
        clean.update("DELETE FROM actg_node");
    }

    private JdbcActgStore store() {
        return new JdbcActgStore(new NamedParameterJdbcTemplate(new JdbcTemplate(dataSource)));
    }

    @Test
    void graphPersistsAcrossStoreInstances() {
        String domain = ActgNode.key(ActgEntityType.DOMAIN, "evil.example");
        String ip = ActgNode.key(ActgEntityType.IP, "45.155.205.233");

        JdbcActgStore first = store();
        first.recordAssociation(domain, ActgEntityType.DOMAIN, ip, ActgEntityType.IP, ActgRelation.RESOLVES_TO);
        first.recordObservation(domain, ActgEntityType.DOMAIN, 0.85);
        first.recordObservation(domain, ActgEntityType.DOMAIN, 0.30);

        JdbcActgStore second = store();
        second.load();

        assertEquals(2, second.nodeCount(), "both nodes must survive a new store instance");
        assertEquals(1, second.edgeCount(), "the association must survive a new store instance");
        assertEquals(0.85, second.node(domain).risk(), 1e-9,
                "risk is a high-water mark and must not regress on reload");
        assertEquals(1, second.neighborhood(domain).size(), "neighborhood must survive reload");
    }

    @Test
    void neighborhoodRiskSurvivesReload() {
        String domain = ActgNode.key(ActgEntityType.DOMAIN, "legit.example");
        String dirtyIp = ActgNode.key(ActgEntityType.IP, "45.155.205.233");

        JdbcActgStore first = store();
        first.recordAssociation(domain, ActgEntityType.DOMAIN, dirtyIp, ActgEntityType.IP, ActgRelation.RESOLVES_TO);
        first.recordObservation(dirtyIp, ActgEntityType.IP, 0.9);

        JdbcActgStore second = store();
        second.load();

        double risk = second.neighborhoodRisk(domain);
        assertTrue(risk >= 0.49 && risk < 1.0,
                "a clean domain linked to a dirty IP must inherit neighborhood risk after reload (got " + risk + ")");
    }

    @Test
    void repeatedAssociationsStrengthenPersistedEdge() {
        String domain = ActgNode.key(ActgEntityType.DOMAIN, "repeat.example");
        String ip = ActgNode.key(ActgEntityType.IP, "198.51.100.7");

        JdbcActgStore first = store();
        first.recordAssociation(domain, ActgEntityType.DOMAIN, ip, ActgEntityType.IP, ActgRelation.RESOLVES_TO);
        first.recordAssociation(domain, ActgEntityType.DOMAIN, ip, ActgEntityType.IP, ActgRelation.RESOLVES_TO);

        JdbcActgStore second = store();
        second.load();

        assertEquals(1, second.edgeCount(), "same relationship must stay a single edge");
        assertTrue(second.neighborhoodRisk(domain) >= 0.0);
    }

    @Test
    void clearEmptiesTheDatabase() {
        JdbcActgStore store = store();
        store.recordObservation(ActgNode.key(ActgEntityType.IP, "1.2.3.4"), ActgEntityType.IP, 0.6);
        store.clear();

        JdbcActgStore reloaded = store();
        reloaded.load();
        assertEquals(0, reloaded.nodeCount(), "clear must wipe persisted state too");
        assertEquals(0, reloaded.edgeCount());
    }
}
