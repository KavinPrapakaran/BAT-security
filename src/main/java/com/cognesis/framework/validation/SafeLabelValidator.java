package com.cognesis.framework.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.regex.Pattern;

public class SafeLabelValidator implements ConstraintValidator<SafeLabel, String> {

    private static final Pattern SAFE = Pattern.compile("^[a-zA-Z0-9 .,\\-_:/@]{1,128}$");

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null || value.isBlank()) return false;
        if (value.contains("..") || value.contains("/") || value.contains("\\")) return false;
        return SAFE.matcher(value).matches();
    }
}
