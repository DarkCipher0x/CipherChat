package systems.darkcipher.cipherchat.crypto

import org.bouncycastle.crypto.kems.MLKEMExtractor
import org.bouncycastle.crypto.params.MLDSAParameters
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters
import org.bouncycastle.crypto.params.MLKEMParameters
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters
import org.bouncycastle.crypto.params.ParametersWithContext
import org.bouncycastle.crypto.signers.MLDSASigner

/**
 * Power-on self-test, the same checks as the web chat's selfTest(): OpenSSL known answers (an implementation independent
 * of BouncyCastle), round trips and tamper cases. The app refuses to unlock if any check fails.
 */
object SelfTest {
    class Check(val name: String, val ok: Boolean)

    fun run(): List<Check> {
        val out = ArrayList<Check>()
        fun check(name: String, ok: Boolean) { out += Check(name, ok); if (!ok) throw CryptoFail("self-test failed: $name") }

        check("SHA3-256 known answer", hex(sha3_256(utf8("abc"))) == "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        val seed = fromHex(Kat.seed32)
        val kem = MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_1024, concat(seed, seed))
        check("ML-KEM-1024 key generation matches OpenSSL", hex(sha3_256(kem.getPublicKey())) == Kat.mlkem1024_pk_sha3)
        check("ML-KEM-1024 decapsulates OpenSSL's ciphertext",
            hex(MLKEMExtractor(kem).extractSecret(unb64(Kat.mlkem1024_ct, Sizes.KEM_CT))) == Kat.mlkem1024_ss)
        val dsa = MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_87, seed)
        check("ML-DSA-87 key generation matches OpenSSL", hex(sha3_256(dsa.getPublicKey())) == Kat.mldsa87_pk_sha3)
        fun katVerify(ctx: String) = MLDSASigner().run {
            init(false, ParametersWithContext(MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_87, dsa.getPublicKey()), utf8(ctx)))
            val m = utf8(Kat.mldsa87_msg); update(m, 0, m.size)
            verifySignature(unb64(Kat.mldsa87_sig, Sizes.SIG_PQ_LEN))
        }
        check("ML-DSA-87 verifies OpenSSL's signature", katVerify(Kat.mldsa87_context))
        check("ML-DSA-87 refuses it under another context", !katVerify("dcx-chat/v1/other"))

        val a = identityFromMaster("selftest-a", random(32))
        val b = identityFromMaster("selftest-b", random(32))
        val k = random(32)
        val w = wrapKey(k, b.kemPqPk, b.kemEcPk, utf8("t"))
        check("hybrid key wrap round trip", sameBytes(unwrapKey(w, b, utf8("t")), k))
        check("hybrid key wrap refuses the wrong recipient", try { unwrapKey(w, a, utf8("t")); false } catch (e: CryptoFail) { true })
        val msg = utf8("dcx")
        val s = sign(a, "t", msg)
        check("hybrid signature verifies", verify(a.sigPqPk, a.sigEcPk, "t", msg, s))
        check("hybrid signature refuses a changed ML-DSA part", !verify(a.sigPqPk, a.sigEcPk, "t", msg, s.copyOf().also { it[10] = (it[10].toInt() xor 1).toByte() }))
        check("hybrid signature refuses a changed Ed25519 part", !verify(a.sigPqPk, a.sigEcPk, "t", msg, s.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }))
        check("hybrid signature is bound to its context", !verify(a.sigPqPk, a.sigEcPk, "u", msg, s))
        a.destroy(); b.destroy()
        return out
    }
}
