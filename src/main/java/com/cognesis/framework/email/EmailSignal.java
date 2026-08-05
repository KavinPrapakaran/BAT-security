package com.cognesis.framework.email;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;

/**
 * One unit of evidence emitted by an email signal analyzer.
 *
 * @param type        which signal family (e.g. EMAIL_AUTH)
 * @param strength    how strongly this signal indicates risk, in [0,1]
 * @param confidence  reliability of this particular measurement, in [0,1]
 * @param explanation why this value was produced (audit trail)
 * @param provenance  where the underlying data came from
 */
public record EmailSignal(
        EvidenceType type,
        double strength,
        double confidence,
        String explanation,
        Provenance provenance) {

    public EmailSignal {
        strength = Math.max(0.0, Math.min(1.0, strength));
        confidence = Math.max(0.0, Math.min(1.0, confidence));
    }
}
