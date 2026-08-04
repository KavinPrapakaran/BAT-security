package com.cognesis.framework.config;

import com.cognesis.framework.algorithm.DecisionBandPolicy;
import com.cognesis.framework.algorithm.SynapseWeights;
import com.cognesis.framework.trust.TrustProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalized configuration for the COGNESIS framework, bound from
 * application.yml under {@code cognesis.*}.
 */
@ConfigurationProperties(prefix = "cognesis")
public class CognesisProperties {

    private final Algorithm algorithm = new Algorithm();
    private final Trust trust = new Trust();
    private final Memory memory = new Memory();
    private final Dns dns = new Dns();
    private final Feed feed = new Feed();
    private final Security security = new Security();

    public static class Algorithm {
        private Band band = new Band();
        private double lowConfidenceThreshold = 0.25;
        private boolean escalateWhenUncertain = true;

        public Band getBand() {
            return band;
        }

        public void setBand(Band band) {
            this.band = band;
        }

        public double getLowConfidenceThreshold() {
            return lowConfidenceThreshold;
        }

        public void setLowConfidenceThreshold(double lowConfidenceThreshold) {
            this.lowConfidenceThreshold = lowConfidenceThreshold;
        }

        public boolean isEscalateWhenUncertain() {
            return escalateWhenUncertain;
        }

        public void setEscalateWhenUncertain(boolean escalateWhenUncertain) {
            this.escalateWhenUncertain = escalateWhenUncertain;
        }

        public DecisionBandPolicy toBandPolicy() {
            return new DecisionBandPolicy(band.getMonitor(), band.getWarn(), band.getChallenge(),
                    band.getEscalate(), band.getIsolate(), band.getBlock(),
                    1.0, lowConfidenceThreshold, escalateWhenUncertain);
        }

        public static class Band {
            private double monitor = 0.30;
            private double warn = 0.45;
            private double challenge = 0.58;
            private double escalate = 0.68;
            private double isolate = 0.82;
            private double block = 0.92;

            public double getMonitor() {
                return monitor;
            }

            public void setMonitor(double monitor) {
                this.monitor = monitor;
            }

            public double getWarn() {
                return warn;
            }

            public void setWarn(double warn) {
                this.warn = warn;
            }

            public double getChallenge() {
                return challenge;
            }

            public void setChallenge(double challenge) {
                this.challenge = challenge;
            }

            public double getEscalate() {
                return escalate;
            }

            public void setEscalate(double escalate) {
                this.escalate = escalate;
            }

            public double getIsolate() {
                return isolate;
            }

            public void setIsolate(double isolate) {
                this.isolate = isolate;
            }

            public double getBlock() {
                return block;
            }

            public void setBlock(double block) {
                this.block = block;
            }
        }
    }

    public static class Trust {
        private double defaultTrust = 0.5;
        private double positiveGain = 0.15;
        private double negativeGain = 0.35;
        private double decayRate = 0.005;
        private double observationsForFullConfidence = 60;
        private double trustGraphInfluence = 0.30;

        public double getDefaultTrust() {
            return defaultTrust;
        }

        public void setDefaultTrust(double defaultTrust) {
            this.defaultTrust = defaultTrust;
        }

        public double getPositiveGain() {
            return positiveGain;
        }

        public void setPositiveGain(double positiveGain) {
            this.positiveGain = positiveGain;
        }

        public double getNegativeGain() {
            return negativeGain;
        }

        public void setNegativeGain(double negativeGain) {
            this.negativeGain = negativeGain;
        }

        public double getDecayRate() {
            return decayRate;
        }

        public void setDecayRate(double decayRate) {
            this.decayRate = decayRate;
        }

        public double getObservationsForFullConfidence() {
            return observationsForFullConfidence;
        }

        public void setObservationsForFullConfidence(double observationsForFullConfidence) {
            this.observationsForFullConfidence = observationsForFullConfidence;
        }

        public double getTrustGraphInfluence() {
            return trustGraphInfluence;
        }

        public void setTrustGraphInfluence(double trustGraphInfluence) {
            this.trustGraphInfluence = trustGraphInfluence;
        }

        public TrustProperties toProperties() {
            return new TrustProperties(defaultTrust, positiveGain, negativeGain,
                    decayRate, observationsForFullConfidence, trustGraphInfluence);
        }
    }

    public static class Memory {
        private double activationDecay = 0.02;
        private int recallLimit = 20;

        public double getActivationDecay() {
            return activationDecay;
        }

        public void setActivationDecay(double activationDecay) {
            this.activationDecay = activationDecay;
        }

        public int getRecallLimit() {
            return recallLimit;
        }

        public void setRecallLimit(int recallLimit) {
            this.recallLimit = recallLimit;
        }
    }

    public static class Dns {
        private Weights weights = new Weights();
        private Live live = new Live();

        public Weights getWeights() {
            return weights;
        }

        public void setWeights(Weights weights) {
            this.weights = weights;
        }

        public Live getLive() {
            return live;
        }

        public void setLive(Live live) {
            this.live = live;
        }

        public SynapseWeights toSynapseWeights() {
            return new SynapseWeights(weights.getEvidence(), weights.getTrust(), weights.getMemory(),
                    weights.getIntent(), weights.getPrediction(), weights.getDeviation(), 0.70);
        }

        public static class Live {
            private boolean enabled = true;
            private String dohUrl = "https://cloudflare-dns.com/dns-query";
            private String dohFallbackUrl = "https://dns.google/resolve";
            private String rdapUrl = "https://rdap.org/domain";
            private String crtUrl = "https://crt.sh";
            private int timeoutSeconds = 6;
            private long cacheTtlSeconds = 300;

            public boolean isEnabled() {
                return enabled;
            }

            public void setEnabled(boolean enabled) {
                this.enabled = enabled;
            }

            public String getDohUrl() {
                return dohUrl;
            }

            public void setDohUrl(String dohUrl) {
                this.dohUrl = dohUrl;
            }

            public String getDohFallbackUrl() {
                return dohFallbackUrl;
            }

            public void setDohFallbackUrl(String dohFallbackUrl) {
                this.dohFallbackUrl = dohFallbackUrl;
            }

            public String getRdapUrl() {
                return rdapUrl;
            }

            public void setRdapUrl(String rdapUrl) {
                this.rdapUrl = rdapUrl;
            }

            public String getCrtUrl() {
                return crtUrl;
            }

            public void setCrtUrl(String crtUrl) {
                this.crtUrl = crtUrl;
            }

            public int getTimeoutSeconds() {
                return timeoutSeconds;
            }

            public void setTimeoutSeconds(int timeoutSeconds) {
                this.timeoutSeconds = timeoutSeconds;
            }

            public long getCacheTtlSeconds() {
                return cacheTtlSeconds;
            }

            public void setCacheTtlSeconds(long cacheTtlSeconds) {
                this.cacheTtlSeconds = cacheTtlSeconds;
            }
        }

        public static class Weights {
            private double evidence = 0.50;
            private double trust = 0.15;
            private double memory = 0.08;
            private double intent = 0.08;
            private double prediction = 0.05;
            private double deviation = 0.04;

            public double getEvidence() {
                return evidence;
            }

            public void setEvidence(double evidence) {
                this.evidence = evidence;
            }

            public double getTrust() {
                return trust;
            }

            public void setTrust(double trust) {
                this.trust = trust;
            }

            public double getMemory() {
                return memory;
            }

            public void setMemory(double memory) {
                this.memory = memory;
            }

            public double getIntent() {
                return intent;
            }

            public void setIntent(double intent) {
                this.intent = intent;
            }

            public double getPrediction() {
                return prediction;
            }

            public void setPrediction(double prediction) {
                this.prediction = prediction;
            }

            public double getDeviation() {
                return deviation;
            }

            public void setDeviation(double deviation) {
                this.deviation = deviation;
            }
        }
    }

    public static class Feed {
        private String url = "";
        private int timeoutSeconds = 10;
        private boolean enabled = false;
        private long refreshMinutes = 60;

        public String getUrl() {
            return url;
        }

        public void setUrl(String url) {
            this.url = url;
        }

        public int getTimeoutSeconds() {
            return timeoutSeconds;
        }

        public void setTimeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
        }

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public long getRefreshMinutes() {
            return refreshMinutes;
        }

        public void setRefreshMinutes(long refreshMinutes) {
            this.refreshMinutes = refreshMinutes;
        }
    }

    /**
     * Access control and rate limiting. Deliberately no default API keys: the
     * service is fail-closed (all protected endpoints return 401/403) until
     * keys are provided via {@code COGNESIS_SECURITY_API_KEYS}.
     */
    public static class Security {
        private String apiKeys = "";
        private boolean rateLimitEnabled = true;
        private int rateLimitPerMinute = 120;
        private int rateLimitBurst = 60;

        public String getApiKeys() {
            return apiKeys;
        }

        public void setApiKeys(String apiKeys) {
            this.apiKeys = apiKeys;
        }

        public boolean isRateLimitEnabled() {
            return rateLimitEnabled;
        }

        public void setRateLimitEnabled(boolean rateLimitEnabled) {
            this.rateLimitEnabled = rateLimitEnabled;
        }

        public int getRateLimitPerMinute() {
            return rateLimitPerMinute;
        }

        public void setRateLimitPerMinute(int rateLimitPerMinute) {
            this.rateLimitPerMinute = rateLimitPerMinute;
        }

        public int getRateLimitBurst() {
            return rateLimitBurst;
        }

        public void setRateLimitBurst(int rateLimitBurst) {
            this.rateLimitBurst = rateLimitBurst;
        }
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public Trust getTrust() {
        return trust;
    }

    public Memory getMemory() {
        return memory;
    }

    public Dns getDns() {
        return dns;
    }

    public Feed getFeed() {
        return feed;
    }

    public Security getSecurity() {
        return security;
    }
}
