package com.cognesis.framework.actg;

/**
 * Semantic relationship labels in the ACTG graph. Each edge carries a relation
 * so that a neighborhood read can distinguish "this IP hosts the domain" from
 * "this user asked for the domain" from "an incident targeted the domain".
 */
public enum ActgRelation {
    RESOLVES_TO,
    REQUESTED_BY,
    SOURCE_FROM,
    ISSUED_FOR,
    ASSOCIATED_WITH,
    TARGET_OF
}
