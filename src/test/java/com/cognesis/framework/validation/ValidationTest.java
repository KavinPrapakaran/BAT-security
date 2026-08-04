package com.cognesis.framework.validation;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ValidationTest {

    private static Validator validator;

    @BeforeAll
    static void setup() {
        try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
            validator = factory.getValidator();
        }
    }

    record EntityIdHolder(@EntityId String entityId) {}
    record DomainNameHolder(@DomainName String domain) {}
    record SafeLabelHolder(@SafeLabel String label) {}

    @Test
    void entityIdRejectsSlash() {
        Set<ConstraintViolation<EntityIdHolder>> violations =
                validator.validate(new EntityIdHolder("../../../etc/passwd"));
        assertFalse(violations.isEmpty());
    }

    @Test
    void entityIdRejectsNull() {
        Set<ConstraintViolation<EntityIdHolder>> violations =
                validator.validate(new EntityIdHolder(null));
        assertFalse(violations.isEmpty());
    }

    @Test
    void entityIdAcceptsValidId() {
        Set<ConstraintViolation<EntityIdHolder>> violations =
                validator.validate(new EntityIdHolder("evil.test.com"));
        assertTrue(violations.isEmpty());
    }

    @Test
    void entityIdAcceptsColon() {
        Set<ConstraintViolation<EntityIdHolder>> violations =
                validator.validate(new EntityIdHolder("ip:10.0.0.1"));
        assertTrue(violations.isEmpty());
    }

    @Test
    void entityIdRejectsTooLong() {
        String longId = "a".repeat(256);
        Set<ConstraintViolation<EntityIdHolder>> violations =
                validator.validate(new EntityIdHolder(longId));
        assertFalse(violations.isEmpty());
    }

    @Test
    void domainNameRejectsPathTraversal() {
        Set<ConstraintViolation<DomainNameHolder>> violations =
                validator.validate(new DomainNameHolder("evil.com/../../etc"));
        assertFalse(violations.isEmpty());
    }

    @Test
    void domainNameAcceptsValidDomain() {
        Set<ConstraintViolation<DomainNameHolder>> violations =
                validator.validate(new DomainNameHolder("evil.test.com"));
        assertTrue(violations.isEmpty());
    }

    @Test
    void domainNameRejectsDoubleDash() {
        Set<ConstraintViolation<DomainNameHolder>> violations =
                validator.validate(new DomainNameHolder("--evil.com"));
        assertFalse(violations.isEmpty());
    }

    @Test
    void safeLabelRejectsPathTraversal() {
        Set<ConstraintViolation<SafeLabelHolder>> violations =
                validator.validate(new SafeLabelHolder("../../etc/passwd"));
        assertFalse(violations.isEmpty());
    }

    @Test
    void safeLabelAcceptsNormalLabel() {
        Set<ConstraintViolation<SafeLabelHolder>> violations =
                validator.validate(new SafeLabelHolder("billing-portal"));
        assertTrue(violations.isEmpty());
    }

    @Test
    void safeLabelRejectsTooLong() {
        String longLabel = "a".repeat(129);
        Set<ConstraintViolation<SafeLabelHolder>> violations =
                validator.validate(new SafeLabelHolder(longLabel));
        assertFalse(violations.isEmpty());
    }
}
