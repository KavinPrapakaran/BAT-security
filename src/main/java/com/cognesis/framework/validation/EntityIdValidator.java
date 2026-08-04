package com.cognesis.framework.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class EntityIdValidator implements ConstraintValidator<EntityId, String> {

    private static final Pattern SAFE = Pattern.compile("^[a-zA-Z0-9._:\\-]{1,255}$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) return false;
        return SAFE.matcher(value).matches();
    }
}
