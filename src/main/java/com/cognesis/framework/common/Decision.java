package com.cognesis.framework.common;

/**
 * The four canonical security decisions emitted by the COGNESIS framework.
 * Ordered from least to most restrictive so that comparison and escalation
 * logic can rely on {@link #ordinal()}.
 */
public enum Decision {
    ALLOW,
    WARN,
    MONITOR,
    BLOCK
}
