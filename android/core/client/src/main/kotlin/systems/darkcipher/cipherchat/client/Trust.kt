package systems.darkcipher.cipherchat.client

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.PublicIdentity
import systems.darkcipher.cipherchat.crypto.Signed64
import systems.darkcipher.cipherchat.crypto.openIdentity
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.verifyCert

/**
 * Who to trust (trust.js, Trust.cs). The only root of trust is the owner's identity fingerprint that YOU compared
 * (safety number) and pinned in your sealed backup. Everyone else is trusted only through a certificate signed by that
 * identity. The server's word counts for nothing here: it can hand out any keys it likes and this refuses them.
 */
class Trust {
    private val opened = HashMap<String, PublicIdentity>()
    private val certs = HashMap<String, Boolean>()

    class Result(val people: Map<String, Person>, val ownerPub: PublicIdentity?, val ownerProblem: String)

    @Synchronized
    fun evaluate(directory: JsonArray, ownerUser: String, anchorFp: String?): Result {
        val people = LinkedHashMap<String, Person>()
        val entries = directory.filterIsInstance<JsonObject>()
        val ownerEntry = entries.firstOrNull { it.strOrNull("user") == ownerUser }
        var ownerPub: PublicIdentity? = null
        var ownerProblem = ""
        val oid = ownerEntry?.get("identity") as? JsonObject
        when {
            anchorFp == null -> ownerProblem = "you haven't verified the owner's identity yet"
            oid == null -> ownerProblem = "the owner has no chat identity on the server"
            oid.strOrNull("fp") != anchorFp -> ownerProblem = "THE OWNER'S KEY ON THE SERVER IS NOT THE ONE YOU VERIFIED"
            else -> try { ownerPub = open(ownerUser, oid) } catch (e: CryptoFail) { ownerProblem = "the owner's identity doesn't verify: " + e.message }
        }
        for (d in entries) {
            val user = d.strOrNull("user") ?: continue
            val name = d.strOrNull("display_name") ?: ""
            val owner = d.flag("owner")
            val ident = d["identity"] as? JsonObject
            val fp = ident?.strOrNull("fp")
            fun p(t: TrustLevel, why: String, pub: PublicIdentity? = null) = Person(user, name, owner, fp, pub, t, why)
            if (ident == null) { people[user] = p(TrustLevel.NONE, "hasn't set up the chat yet"); continue }
            if (user == ownerUser) {
                people[user] = if (ownerPub != null) p(TrustLevel.OK, "the owner (you verified this key)", ownerPub) else p(TrustLevel.BAD, ownerProblem)
                continue
            }
            val op = ownerPub
            if (op == null) { people[user] = p(TrustLevel.BAD, "can't check: $ownerProblem"); continue }
            val pub = try { open(user, ident) } catch (e: CryptoFail) { people[user] = p(TrustLevel.BAD, "identity doesn't verify: " + e.message); continue }
            val cert = d["cert"] as? JsonObject
            if (cert == null) { people[user] = p(TrustLevel.PENDING, "waiting for the owner to verify and certify"); continue }
            val s = cert.strOrNull("s") ?: ""
            val key = user + "|" + fp + "|" + s.take(64) + "|" + op.fp
            val ok = certs.getOrPut(key) {
                try { verifyCert(Signed64(cert.strOrNull("b") ?: "", s), op, user, fp!!) } catch (e: CryptoFail) { false }
            }
            people[user] = if (ok) p(TrustLevel.OK, "certified by the owner", pub) else p(TrustLevel.BAD, "the certificate doesn't verify")
        }
        return Result(people, ownerPub, ownerProblem)
    }

    private fun open(user: String, ident: JsonObject): PublicIdentity {
        val k = user + "|" + ident.strOrNull("fp")
        return opened.getOrPut(k) {
            val pub = openIdentity(ident.str("b"), ident.str("s"), user)
            if (pub.fp != ident.strOrNull("fp")) throw CryptoFail("fingerprint mismatch")
            pub
        }
    }
}
