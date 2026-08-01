package com.cognesis.framework.intent;

/**
 * MOTIVE - the intent engine. Given the set of observed evidence families, it
 * reasons about what the actor is attempting (recon, phishing, command &
 * control, exfiltration, abuse, ...). Intent is one of the signals fused by
 * SYNAPSE: an analyst always asks "what is the attacker trying to do?".
 */
public interface IntentEngine {

    IntentAssessment assess(IntentContext context);
}
