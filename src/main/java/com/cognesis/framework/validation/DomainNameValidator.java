package com.cognesis.framework.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class DomainNameValidator implements ConstraintValidator<DomainName, String> {

    private static final Pattern DOMAIN = Pattern.compile(
            "^(?!-)[a-zA-Z0-9\\-]{1,63}(\\.[a-zA-Z0-9\\-]{1,63})*\\.[a-zA-Z]{2,}$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) return false;
        if (value.length() > 255) return false;
        return DOMAIN.matcher(value).matches();
    }
}
