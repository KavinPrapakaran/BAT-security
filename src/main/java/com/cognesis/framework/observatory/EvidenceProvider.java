package com.cognesis.framework.observatory;

import java.util.List;

/**
 * A pluggable source of evidence. The framework ships a DNS provider; new
 * providers (Cloud, Identity, Email, API, IoT, Endpoint, Threat Intelligence)
 * implement this interface and register as Spring beans without any change to
 * the decision core.
 */
public interface EvidenceProvider {

    List<EvidenceFragment> provide(EvidenceRequest request);
}
