package systems.darkcipher.cipherchat.client

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import systems.darkcipher.cipherchat.crypto.Backup
import systems.darkcipher.cipherchat.crypto.Canon
import systems.darkcipher.cipherchat.crypto.CryptoFail
import systems.darkcipher.cipherchat.crypto.Identity
import systems.darkcipher.cipherchat.crypto.b64
import systems.darkcipher.cipherchat.crypto.identityFromMaster
import systems.darkcipher.cipherchat.crypto.long
import systems.darkcipher.cipherchat.crypto.openIdentity
import systems.darkcipher.cipherchat.crypto.publishIdentity
import systems.darkcipher.cipherchat.crypto.random
import systems.darkcipher.cipherchat.crypto.safetyNumber
import systems.darkcipher.cipherchat.crypto.str
import systems.darkcipher.cipherchat.crypto.strOrNull
import systems.darkcipher.cipherchat.crypto.unb64
import systems.darkcipher.cipherchat.crypto.wipe

/** This device's unlocked identity: keys live in memory only, until [ChatEngine.lock]. */
class Me internal constructor(internal val id: Identity, val fp: String, anchorFp: String?) {
    val user: String get() = id.user
    @Volatile var anchorFp: String? = anchorFp
        internal set
}

/** A wrong chat passphrase. */
class WrongPassphrase(message: String) : Exception(message)

internal fun JsonObject.obj(k: String): JsonObject = this[k] as? JsonObject ?: throw CryptoFail("missing $k")

/**
 * The steps in front of the chat (gate.js, Gate.cs): create an identity, unlock it with the chat passphrase, pin the
 * owner's identity after comparing safety numbers, change the passphrase. The passphrase is a CharArray the caller
 * wipes; it is never stored or sent.
 */
object Gate {
    const val MIN_PASS = 16

    fun passProblems(p: CharArray): String? {
        if (p.size < MIN_PASS) return "Use at least $MIN_PASS characters (4 or more random words works well)."
        if (p.toSet().size < 8) return "That has too few different characters."
        return null
    }

    private fun nowMs() = System.currentTimeMillis()

    private suspend fun sealBackup(api: ChatApi, user: String, passphrase: CharArray, payload: JsonObject): JsonObject {
        val pep = api.call("pepper")
        return withContext(Dispatchers.Default) { Backup.seal(user, passphrase, unb64(pep.str("pepper"), 32), pep.long("pepper_ver").toInt(), payload) }
    }

    private suspend fun openBackup(api: ChatApi, user: String, passphrase: CharArray, wrong: String): Pair<JsonObject, JsonObject> {
        val b = api.call("backup/fetch", JsonObject(emptyMap()))
        val payload = try { withContext(Dispatchers.Default) { Backup.open(user, passphrase, unb64(b.str("pepper"), 32), b.obj("backup")) } }
                      catch (e: CryptoFail) { if (e.message == "wrong passphrase") throw WrongPassphrase(wrong) else throw e }
        return b to payload
    }

    /** First time on any device (or a deliberate reset): make the identity, seal it, publish it. */
    suspend fun setup(api: ChatApi, state: JsonObject, passphrase: CharArray, reset: Boolean, ask: AskCode?, progress: (String) -> Unit = {}): Me {
        passProblems(passphrase)?.let { throw IllegalArgumentException(it) }
        val me = state.obj("me")
        val user = me.str("user")
        val owner = me.flag("owner")
        progress("Generating ML-KEM-1024, X25519, ML-DSA-87 and Ed25519 keys…")
        val master = random(32)
        try {
            val id = withContext(Dispatchers.Default) { identityFromMaster(user, master) }
            val pub = publishIdentity(id, nowMs())
            val anchor = if (owner) pub.fp else null                          // the owner is the trust anchor; members pin it next
            progress("Sealing your keys with Argon2id (64 MiB)…")
            val payload = buildJsonObject {
                put("v", 1); put("master", b64(master)); put("anchor_fp", anchor?.let(::JsonPrimitive) ?: JsonNull); put("created", nowMs())
            }
            val backup = sealBackup(api, user, passphrase, payload)
            progress("Publishing your public keys…")
            api.call("identity", buildJsonObject {
                put("bundle", buildJsonObject { put("b", pub.b); put("s", pub.s) }); put("backup", backup); put("confirm_reset", reset)
            }, ask)
            return Me(id, pub.fp, anchor)
        } finally { wipe(master) }
    }

    /** Opens the sealed identity with the chat passphrase and checks the server publishes exactly these keys. */
    suspend fun unlock(api: ChatApi, state: JsonObject, passphrase: CharArray, progress: (String) -> Unit = {}): Me {
        val user = state.obj("me").str("user")
        progress("Fetching your sealed keys…")
        val (b, payload) = openBackup(api, user, passphrase, "That passphrase isn't right.")
        progress("Rebuilding your keys…")
        val master = unb64(payload.str("master"), 32)
        try {
            val id = withContext(Dispatchers.Default) { identityFromMaster(user, master) }
            val at = Canon.parseSigned(b.obj("bundle").str("b"), 16384).obj.long("at")
            if (publishIdentity(id, at).fp != b.str("fp"))
                throw CryptoFail("The identity the server shows for you doesn't match your keys. Don't use the chat; tell the owner.")
            return Me(id, b.str("fp"), payload.strOrNull("anchor_fp"))
        } finally { wipe(master) }
    }

    /** The 60 digits to compare with the owner, or null if the owner has no identity yet. */
    fun ownerSafetyNumber(state: JsonObject, me: Me): String? = ownerIdentity(state)?.let { safetyNumber(me.fp, it.str("fp")) }

    fun ownerIdentity(state: JsonObject): JsonObject? {
        val ownerUser = state.str("owner")
        return ((state["directory"] as? JsonArray)?.filterIsInstance<JsonObject>()?.firstOrNull { it.strOrNull("user") == ownerUser })?.get("identity") as? JsonObject
    }

    /** After the person confirmed the safety number matches: pin the owner's fingerprint inside the sealed backup. */
    suspend fun pinOwner(api: ChatApi, state: JsonObject, me: Me, passphrase: CharArray, ask: AskCode?) {
        val owner = ownerIdentity(state) ?: throw IllegalStateException("The owner hasn't set up their chat identity yet.")
        openIdentity(owner.str("b"), owner.str("s"), state.str("owner"), owner.str("fp"))   // must be a valid, self-signed identity
        val (_, payload) = openBackup(api, me.user, passphrase, "That passphrase isn't right.")
        val next = JsonObject(payload + ("anchor_fp" to JsonPrimitive(owner.str("fp"))))
        val backup = sealBackup(api, me.user, passphrase, next)
        api.call("backup", buildJsonObject { put("fp", me.fp); put("backup", backup) }, ask)
        me.anchorFp = owner.str("fp")
    }

    suspend fun changePassphrase(api: ChatApi, me: Me, current: CharArray, next: CharArray, ask: AskCode?) {
        passProblems(next)?.let { throw IllegalArgumentException(it) }
        val (_, payload) = openBackup(api, me.user, current, "The current passphrase isn't right.")
        val backup = sealBackup(api, me.user, next, payload)
        api.call("backup", buildJsonObject { put("fp", me.fp); put("backup", backup) }, ask)
    }
}
