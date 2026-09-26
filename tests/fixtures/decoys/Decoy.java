/* Adversarial decoy fixture -- Java.
 * Every algorithm name here is a STRING ARGUMENT or a COMMENT, not an invocation.
 * `KeyPairGenerator.getInstance("RSA")` is the hard case: a naive scanner sees an algorithm name
 * and reports it, but generating a key proves nothing about what the key is FOR. This is exactly
 * the case the purpose model must report as UNRESOLVED rather than guessing ML-KEM.
 */

/**
 * Historical note: we previously used RSA and ECDSA here. AES-256 remains.
 * The cipher list once contained TLS_RSA_WITH_AES_128_GCM_SHA256.
 */
public class LegacyNote {

    private static final String MIGRATION_REFERENCE = "ML-KEM-768, ML-DSA-44";

    // A digest of some content, not key material:
    private static final String FAKE_BLOB =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    public String describe() {
        return "Originally wrapped RSA. Retained for the migration audit only.";
    }

    public String reference() {
        return MIGRATION_REFERENCE;
    }
}
