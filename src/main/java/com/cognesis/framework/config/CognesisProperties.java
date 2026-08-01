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
            return new DecisionBandPolicy(band.getWarn(), band.getMonitor(), band.getBlock(),
                    1.0, lowConfidenceThreshold, escalateWhenUncertain);
        }

        public static class Band {
            private double warn = 0.32;
            private double monitor = 0.55;
            private double block = 0.80;

            public double getWarn() {
                return warn;
            }

            public void setWarn(double warn) {
                this.warn = warn;
            }

            public double getMonitor() {
                return monitor;
            }

            public void setMonitor(double monitor) {
                this.monitor = monitor;
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

        public Weights getWeights() {
            return weights;
        }

        public void setWeights(Weights weights) {
            this.weights = weights;
        }

        public SynapseWeights toSynapseWeights() {
            return new SynapseWeights(weights.getEvidence(), weights.getTrust(), weights.getMemory(),
                    weights.getIntent(), weights.getPrediction(), weights.getDeviation(), 0.70);
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
}
