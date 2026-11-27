/**
 * Domain model: credentials, the vault manager and the master user.
 *
 * <p>Secrets are represented as {@code char[]}/{@code byte[]} and wiped after
 * use. {@code toString()} implementations must never expose decrypted secrets.</p>
 */
package model;
