package com.cognesis.framework.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.*;

@Documented
@Constraint(validatedBy = DomainNameValidator.class)
@Target({ElementType.PARAMETER, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface DomainName {
    String message() default "Invalid domain name";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
