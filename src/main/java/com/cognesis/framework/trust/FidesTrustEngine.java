package com.cognesis.framework.trust;

import com.cognesis.framework.persistence.TrustProfile;
import com.cognesis.framework.persistence.TrustProfileStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default FIDES implementation. Runs in-memory with an optional
 * {@link TrustProfileStore} (JDBC) for persistence - the persistence layer can
 * be swapped without changing callers.
 *
 * <h2>Update rule</h2>
 * <pre>
 *   positive event:  T += (1 - T) * alpha_p * strength
 *   negative event:  T -= T        * alpha_n * strength     (alpha_n > alpha_p)
 *   time decay:      T += (0.5 - T) * (1 - exp(-lambda * dt))   regression to neutral
 *   confidence:      K = 1 - exp(-observations / N0)
 *   graph influence: T_final = (1-g)*T_own + g*mean(neighbour trust)
 * </pre>
 */
public class FidesTrustEngine implements TrustEngine {

    private static final Logger log = LoggerFactory.getLogger(FidesTrustEngine.class);

    private static final class Profile {
        double trust;
        long observations;
        Instant lastUpdated;
        final List<TrustEvent> history = new ArrayList<>();

        Profile(double trust) {
            this.trust = trust;
            this.lastUpdated = Instant.now();
        }
    }

    private final TrustProperties properties;
    private final TrustProfileStore profileStore;
    private final Map<String, Profile> profiles = new ConcurrentHashMap<>();

    public FidesTrustEngine(TrustProperties properties) {
        this(properties, new TrustProfileStore() {
        });
    }

    public FidesTrustEngine(TrustProperties properties, TrustProfileStore profileStore) {
        this.properties = properties != null ? properties : TrustProperties.defaults();
        this.profileStore = profileStore != null ? profileStore : new TrustProfileStore() {
        };
    }

    @Override
    public TrustAssessment assess(String entityId, String entityType) {
        return assess(new TrustContext(entityId, entityType, Map.of()));
    }

    @Override
    public TrustAssessment assess(TrustContext context) {
        Profile profile = loadIfMissing(context.entityId(), context.entityType());
        profile = applyDecay(context.entityId(), Instant.now());
        double own = profile != null ? profile.trust : properties.defaultTrust();
        double confidence = confidenceFor(profile);
        if (!context.neighbourTrusts().isEmpty()) {
            double avgNeighbour = context.neighbourTrusts().values().stream()
                    .mapToDouble(Double::doubleValue)
                    .average().orElse(own);
            double g = properties.trustGraphInfluence();
            own = own * (1.0 - g) + avgNeighbour * g;
        }
        return new TrustAssessment(
                context.entityId(),
                clamp(own),
                confidence,
                profile != null ? profile.observations : 0,
                profile != null ? profile.lastUpdated : Instant.EPOCH,
                profile != null ? List.copyOf(profile.history) : List.of());
    }

    @Override
    public TrustAssessment recordEvent(TrustEvent event) {
        Profile profile = profiles.computeIfAbsent(event.entityId(), k -> new Profile(properties.defaultTrust()));
        profile = applyDecay(event.entityId(), event.occurredAt());

        switch (event.eventType()) {
            case POSITIVE -> profile.trust += (1.0 - profile.trust) * properties.positiveGain() * event.strength();
            case NEGATIVE -> profile.trust -= profile.trust * properties.negativeGain() * event.strength();
            case DECAY -> { /* decay already applied */ }
        }
        profile.trust = clamp(profile.trust);
        profile.observations++;
        profile.lastUpdated = event.occurredAt();
        profile.history.add(event);
        if (profile.history.size() > 100) {
            profile.history.remove(0);
        }
        TrustProfile snapshot = new TrustProfile(event.entityId(), "UNKNOWN",
                profile.trust, confidenceFor(profile), profile.observations, profile.lastUpdated);
        profileStore.save(snapshot);
        log.info("Trust[{}] -> {} (event={}, strength={})",
                event.entityId(), String.format("%.3f", profile.trust), event.eventType(), event.strength());
        return assess(event.entityId(), "UNKNOWN");
    }

    private Profile loadIfMissing(String entityId, String entityType) {
        if (profiles.containsKey(entityId)) {
            return profiles.get(entityId);
        }
        return profileStore.load(entityId)
                .map(p -> {
                    Profile restored = new Profile(p.trust());
                    restored.observations = p.observationCount();
                    restored.lastUpdated = p.lastUpdated();
                    profiles.put(entityId, restored);
                    return restored;
                })
                .orElse(null);
    }

    private Profile applyDecay(String entityId, Instant now) {
        Profile profile = profiles.get(entityId);
        if (profile == null) {
            return null;
        }
        long hours = Duration.between(profile.lastUpdated, now).toHours();
        if (hours > 0) {
            double decay = 1.0 - Math.exp(-properties.decayRate() * hours);
            profile.trust += (properties.defaultTrust() - profile.trust) * decay;
            profile.trust = clamp(profile.trust);
            profile.lastUpdated = now;
        }
        return profile;
    }

    private double confidenceFor(Profile profile) {
        if (profile == null) {
            return 0.0;
        }
        return 1.0 - Math.exp(-profile.observations / properties.observationsForFullConfidence());
    }

    private static double clamp(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
