-- Organization Profiles (v1.2.0): org-scoped risk tolerance and policy rules.
ALTER TABLE policy_rule ADD COLUMN IF NOT EXISTS organization_id TEXT;

CREATE TABLE IF NOT EXISTS organization_profile (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    risk_tolerance DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO organization_profile (organization_id, name, risk_tolerance, updated_at)
SELECT 'hospital', 'Regional Hospital', 0.70, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM organization_profile WHERE organization_id = 'hospital');

INSERT INTO organization_profile (organization_id, name, risk_tolerance, updated_at)
SELECT 'bank', 'First National Bank', 0.80, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM organization_profile WHERE organization_id = 'bank');

INSERT INTO organization_profile (organization_id, name, risk_tolerance, updated_at)
SELECT 'university', 'State University', 1.20, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM organization_profile WHERE organization_id = 'university');
