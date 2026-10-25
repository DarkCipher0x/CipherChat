package systems.darkcipher.cipherchat.crypto

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA3Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.kems.MLKEMGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithContext
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.crypto.signers.MLDSASigner
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The DarkCipher chat protocol's cryptography, a Kotlin port of the web chat's crypto.js and byte-for-byte compatible
 * with it (cross-checked in the tests against OpenSSL 3.5 and against output made by the browser).
 *
 * Hybrid post-quantum throughout, so each step stays secure while EITHER half holds:
 *   key wrapping   ML-KEM-1024 (FIPS 203) + X25519, both secrets and the whole transcript through HKDF-SHA-512
 *   signatures     ML-DSA-87 (FIPS 204, with a context string) + Ed25519; valid only if BOTH verify
 *   symmetric      AES-256-GCM; SHA3-256/512 for fingerprints and commitments
 * All of it is BouncyCastle (pinned by SHA-256 in gradle/verification-metadata.xml) except AES-GCM, which is the
 * platform's (Conscrypt on Android).
 */
object Sizes {
    const val KEM_PQ = 1568; const val KEM_EC = 32; const val SIG_PQ = 2592; const val SIG_EC = 32
    const val KEM_CT = 1568; const val SIG_PQ_LEN = 4627; const val SIG_EC_LEN = 64
    const val SIG = SIG_PQ_LEN + SIG_EC_LEN
    const val WRAP = 1568 + 32 + 12 + 32 + 16
}

const val SUITE = "ML-KEM-1024+X25519 / ML-DSA-87+Ed25519 / AES-256-GCM / SHA-3"

// ------------------------------------------------------------------------------------------------ primitives
fun sha3_256(vararg parts: ByteArray): ByteArray = sha3(256, parts)
fun sha3_512(vararg parts: ByteArray): ByteArray = sha3(512, parts)
private fun sha3(bits: Int, parts: Array<out ByteArray>): ByteArray {
    val d = SHA3Digest(bits)
    for (p in parts) d.update(p, 0, p.size)
    return ByteArray(bits / 8).also { d.doFinal(it, 0) }
}

/** HKDF-SHA-512 to a 32-byte AES-256 key (what WebCrypto's deriveKey(HKDF -> AES-GCM 256) produces). */
internal fun hkdf32(ikm: ByteArray, salt: ByteArray, info: String): ByteArray {
    val g = HKDFBytesGenerator(SHA512Digest())
    g.init(HKDFParameters(ikm, salt, utf8(info)))
    return ByteArray(32).also { g.generateBytes(it, 0, 32) }
}

/** AES-256-GCM: nonce(12) || ciphertext || tag(16). */
internal fun aesSeal(key: ByteArray, plain: ByteArray, aad: ByteArray): ByteArray {
    val nonce = random(12)
    val c = Cipher.getInstance("AES/GCM/NoPadding")
    c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    c.updateAAD(aad)
    return concat(nonce, c.doFinal(plain))
}

internal fun aesOpen(key: ByteArray, sealed: ByteArray, aad: ByteArray): ByteArray {
    if (sealed.size < 12 + 16) throw CryptoFail("ciphertext too short")
    return try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, sealed, 0, 12))
        c.updateAAD(aad)
        c.doFinal(sealed, 12, sealed.size - 12)
    } catch (e: java.security.GeneralSecurityException) {
        throw CryptoFail("decryption failed (wrong key or the data was changed)")
    }
}

private fun x25519(priv: X25519PrivateKeyParameters, pub: ByteArray): ByteArray {
    val out = ByteArray(32)
    try {
        X25519Agreement().apply { init(priv) }.calculateAgreement(X25519PublicKeyParameters(pub, 0), out, 0)
    } catch (e: IllegalStateException) {
        throw CryptoFail("invalid X25519 key")                 // BouncyCastle refuses an all-zero (low-order) result
    }
    if (out.all { it == 0.toByte() }) throw CryptoFail("invalid X25519 key")
    return out
}

// ------------------------------------------------------------------------------------------------ identities
/** A person's private identity, derived from one 32-byte master secret (so a new device rebuilds identical keys). */
class Identity internal constructor(
    val user: String,
    internal val kemPq: MLKEMPrivateKeyParameters,
    val kemPqPk: ByteArray,
    internal val kemEc: X25519PrivateKeyParameters,
    val kemEcPk: ByteArray,
    internal val sigPq: MLDSAPrivateKeyParameters,
    val sigPqPk: ByteArray,
    internal val sigEc: Ed25519PrivateKeyParameters,
    val sigEcPk: ByteArray,
) {
    fun destroy() { kemPq.destroy(); sigPq.destroy() }
}

/** Someone's verified public identity (self-signature checked by [openIdentity]). */
class PublicIdentity(
    val user: String, val fp: String, val at: Long,
    val kemPq: ByteArray, val kemEc: ByteArray, val sigPq: ByteArray, val sigEc: ByteArray,
)

private fun derive(master: ByteArray, label: String, len: Int): ByteArray {
    val input = concat(utf8("dcx-chat/v1/seed/$label|"), master)
    return if (len == 64) sha3_512(input) else sha3_256(input)
}

fun identityFromMaster(user: String, master: ByteArray): Identity {
    if (master.size != 32) throw CryptoFail("bad master secret")
    val kemSeed = derive(master, "kem-pq", 64)
    val sigSeed = derive(master, "sig-pq", 32)
    val xSeed = derive(master, "kem-ec", 32)
    val edSeed = derive(master, "sig-ec", 32)
    try {
        val kem = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, kemSeed)      // FIPS 203 keygen from d || z
        val sig = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, sigSeed)        // FIPS 204 keygen from xi
        val x = X25519PrivateKeyParameters(xSeed, 0)
        val ed = Ed25519PrivateKeyParameters(edSeed, 0)
        return Identity(user, kem, kem.getPublicKey(), x, x.generatePublicKey().encoded,
            sig, sig.getPublicKey(), ed, ed.generatePublicKey().encoded)
    } finally {
        wipe(kemSeed, sigSeed, xSeed, edSeed)
    }
}

class Published(val b: String, val s: String, val fp: String)

/** The signed public half everyone else uses. */
fun publishIdentity(id: Identity, at: Long): Published {
    val raw = Canon.bytes(buildJsonObject {
        put("v", 1); put("t", "identity"); put("user", id.user); put("at", at)
        put("kem_pq", b64(id.kemPqPk)); put("kem_ec", b64(id.kemEcPk)); put("sig_pq", b64(id.sigPqPk)); put("sig_ec", b64(id.sigEcPk))
    })
    return Published(b64(raw), b64(sign(id, "dcx-chat/v1/identity", raw)), hex(sha3_256(raw)))
}

/** Someone else's published identity -> verified public keys. WHO it belongs to comes from the owner's certificate. */
fun openIdentity(b: String, s: String, expectUser: String, expectFp: String? = null): PublicIdentity {
    val sig = Canon.parseSigned(b, 16384)
    val o = sig.obj
    if (o.str("t") != "identity" || o.str("user") != expectUser) throw CryptoFail("identity is for someone else")
    val fp = hex(sha3_256(sig.raw))
    if (expectFp != null && expectFp != fp) throw CryptoFail("fingerprint mismatch")
    val pub = PublicIdentity(expectUser, fp, o.long("at"),
        unb64(o.str("kem_pq"), Sizes.KEM_PQ), unb64(o.str("kem_ec"), Sizes.KEM_EC),
        unb64(o.str("sig_pq"), Sizes.SIG_PQ), unb64(o.str("sig_ec"), Sizes.SIG_EC))
    if (!verify(pub.sigPq, pub.sigEc, "dcx-chat/v1/identity", sig.raw, unb64(s))) throw CryptoFail("identity self-signature is invalid")
    return pub
}

// ------------------------------------------------------------------------------------------------ hybrid signatures
fun sign(id: Identity, label: String, msg: ByteArray): ByteArray {
    val pq = MLDSASigner()
    // hedged signing (fresh randomness), with the FIPS 204 context string = the purpose label
    pq.init(true, ParametersWithContext(ParametersWithRandom(id.sigPq, rng), utf8(label)))
    pq.update(msg, 0, msg.size)
    val s1 = pq.generateSignature()
    val ec = Ed25519Signer()
    ec.init(true, id.sigEc)
    val m2 = concat(utf8(label), byteArrayOf(0), msg)
    ec.update(m2, 0, m2.size)
    return concat(s1, ec.generateSignature())
}

fun verify(pub: PublicIdentity, label: String, msg: ByteArray, sig: ByteArray) = verify(pub.sigPq, pub.sigEc, label, msg, sig)

/** BOTH halves must verify; a malformed signature is simply false. */
fun verify(sigPqPk: ByteArray, sigEcPk: ByteArray, label: String, msg: ByteArray, sig: ByteArray): Boolean {
    if (sig.size != Sizes.SIG) return false
    val pq = try {
        MLDSASigner().run {
            init(false, ParametersWithContext(MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, sigPqPk), utf8(label)))
            update(msg, 0, msg.size)
            verifySignature(sig.copyOfRange(0, Sizes.SIG_PQ_LEN))
        }
    } catch (e: Exception) { false }
    val ec = try {
        Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(sigEcPk, 0))
            val m2 = concat(utf8(label), byteArrayOf(0), msg)
            update(m2, 0, m2.size)
            verifySignature(sig.copyOfRange(Sizes.SIG_PQ_LEN, Sizes.SIG))
        }
    } catch (e: Exception) { false }
    return pq && ec
}

// ------------------------------------------------------------------------------------------------ hybrid key wrapping
/** Wraps a 32-byte key for one recipient: ML-KEM ct (1568) || X25519 ephemeral (32) || nonce (12) || GCM (48). */
fun wrapKey(key32: ByteArray, rcptKemPq: ByteArray, rcptKemEc: ByteArray, aad: ByteArray): ByteArray {
    val enc = MLKEMGenerator(rng).generateEncapsulated(MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_1024, rcptKemPq))
    val ssPq = enc.secret
    val ct = enc.encapsulation
    val eph = X25519PrivateKeyParameters(rng)
    val ephPub = eph.generatePublicKey().encoded
    val ssEc = x25519(eph, rcptKemEc)
    val wk = wrapKdf(ssPq, ssEc, ct, ephPub, rcptKemPq, rcptKemEc)
    wipe(ssPq, ssEc)
    try { return concat(ct, ephPub, aesSeal(wk, key32, aad)) } finally { wipe(wk) }
}

fun unwrapKey(wrapped: ByteArray, id: Identity, aad: ByteArray): ByteArray {
    if (wrapped.size != Sizes.WRAP) throw CryptoFail("wrapped key has the wrong length")
    val ct = wrapped.copyOfRange(0, 1568)
    val ephPub = wrapped.copyOfRange(1568, 1600)
    val sealed = wrapped.copyOfRange(1600, wrapped.size)
    val ssPq = MLKEMExtractor(id.kemPq).extractSecret(ct)       // implicit rejection: a wrong ct gives a random secret
    val ssEc = x25519(id.kemEc, ephPub)
    val wk = wrapKdf(ssPq, ssEc, ct, ephPub, id.kemPqPk, id.kemEcPk)
    wipe(ssPq, ssEc)
    try {
        val key = aesOpen(wk, sealed, aad)
        if (key.size != 32) throw CryptoFail("wrapped key has the wrong length")
        return key
    } finally { wipe(wk) }
}

/** "KitchenSink" combiner: both secrets are the key material; both ciphertexts and both recipient keys are in the salt. */
private fun wrapKdf(ssPq: ByteArray, ssEc: ByteArray, ct: ByteArray, ephPub: ByteArray, kemPq: ByteArray, kemEc: ByteArray): ByteArray {
    val salt = sha3_512(utf8("dcx-chat/v1/wrap-transcript|"), ct, ephPub, kemPq, kemEc)
    val ikm = concat(ssPq, ssEc)
    try { return hkdf32(ikm, salt, "dcx-chat/v1/wrap-key") } finally { wipe(ikm) }
}

// ------------------------------------------------------------------------------------------------ fingerprints
fun fpGroups(fp: String): String = fp.chunked(4).joinToString(" ")

/** 60 digits both people see identically; reading them to each other verifies both keys at once. */
fun safetyNumber(fpA: String, fpB: String): String {
    val (x, y) = listOf(fpA, fpB).sorted()
    val h = sha3_512(utf8("dcx-chat/v1/safety|$x|$y"))
    return (0 until 12).joinToString(" ") { i ->
        var n = 0L
        for (j in 0 until 5) n = n * 256 + (h[i * 5 + j].toInt() and 0xff)
        (n % 100000).toString().padStart(5, '0')
    }
}

// ------------------------------------------------------------------------------------------------ certificates
class Signed64(val b: String, val s: String)

fun makeCert(owner: Identity, ownerFp: String, user: String, fp: String, at: Long): Signed64 {
    val raw = Canon.bytes(buildJsonObject {
        put("v", 1); put("t", "cert"); put("user", user); put("fp", fp); put("by", owner.user); put("by_fp", ownerFp); put("at", at)
    })
    return Signed64(b64(raw), b64(sign(owner, "dcx-chat/v1/cert", raw)))
}

fun verifyCert(cert: Signed64, ownerPub: PublicIdentity, user: String, fp: String): Boolean {
    val s = try { Canon.parseSigned(cert.b, 1024) } catch (e: CryptoFail) { return false }
    val o: JsonObject = s.obj
    if (o.strOrNull("t") != "cert" || o.strOrNull("user") != user || o.strOrNull("fp") != fp ||
        o.strOrNull("by") != ownerPub.user || o.strOrNull("by_fp") != ownerPub.fp) return false
    return verify(ownerPub, "dcx-chat/v1/cert", s.raw, try { unb64(cert.s) } catch (e: CryptoFail) { return false })
}
