package com.cognesis.framework.actg;

/**
 * The entity types the ACTG graph reasons about. Everything the framework sees
 * - a user, a device, a domain, a certificate, an IP, an incident - becomes a
 * typed node so relationships between them can be weighed.
 */
public enum ActgEntityType {
    USER,
    DEVICE,
    DOMAIN,
    CERTIFICATE,
    IP,
    INCIDENT
}
