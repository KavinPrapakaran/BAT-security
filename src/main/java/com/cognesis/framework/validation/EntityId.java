package com.cognesis.framework.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = EntityIdValidator.class)
@Target({ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface EntityId {
    String message() default "Invalid entity ID: must be 1-255 chars, alphanumeric with dots/hyphens/underscores/colons only";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
