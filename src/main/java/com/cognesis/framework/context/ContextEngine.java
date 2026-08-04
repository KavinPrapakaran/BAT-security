package com.cognesis.framework.context;

/**
 * CONTEXT - the environment engine. It understands the situation in which a
 * decision is being made (routing, authentication, email, API call, ...) and
 * quantifies how much the environment itself should influence the verdict and
 * how much weight its influence carries.
 */
public interface ContextEngine {

    ContextAssessment assess(ContextInput input);
}
