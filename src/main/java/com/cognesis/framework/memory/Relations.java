package com.cognesis.framework.memory;

/**
 * Canonical relationship vocabulary of the MNEMONIC cyber memory. Relationships
 * turn isolated events into a connected knowledge graph so that reasoning can
 * follow associations: Domain &lt;-&gt; IP, Domain &lt;-&gt; Certificate,
 * User &lt;-&gt; Device, Attack &lt;-&gt; Technique, Decision &lt;-&gt; Outcome.
 */
public final class Relations {

    private Relations() {
    }

    public static final String RESOLVES_TO = "RESOLVES_TO";
    public static final String HAS_CERTIFICATE = "HAS_CERTIFICATE";
    public static final String USED_BY = "USED_BY";
    public static final String USES_TECHNIQUE = "USES_TECHNIQUE";
    public static final String CONNECTED_TO = "CONNECTED_TO";
    public static final String REQUESTED_BY = "REQUESTED_BY";
    public static final String ORIGINATED_FROM = "ORIGINATED_FROM";
    public static final String DECIDED_ON = "DECIDED_ON";
    public static final String OUTCOME_OF = "OUTCOME_OF";
}
