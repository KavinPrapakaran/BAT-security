package com.cognesis.framework.dns;

import com.cognesis.framework.common.EvidenceType;
import com.cognesis.framework.common.Provenance;

/**
 * One unit of evidence emitted by a DNS signal analyzer.
 *
 * @param type        which signal family (e.g. DNS_DGA)
 * @param strength    how strongly this signal indicates risk, in [0,1]
 * @param confidence  reliability of this particular measurement, in [0,1]
 * @param explanation why this value was produced (audit trail)
 * @param provenance  where the underlying data came from
 */
public record DnsSignal(
        EvidenceType type,
        double strength,
        double confidence,
        String explanation,
        Provenance provenance) {

    public DnsSignal {
        strength = Math.max(0.0, Math.min(1.0, strength));
        confidence = Math.max(0.0, Math.min(1.0, confidence));
    }
}
