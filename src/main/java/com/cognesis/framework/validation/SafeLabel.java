package com.cognesis.framework.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = SafeLabelValidator.class)
@Target({ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface SafeLabel {
    String message() default "Invalid label: must be 1-128 chars, no path traversal or injection characters";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
