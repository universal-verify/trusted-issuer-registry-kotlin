package com.universalverify.trustedissuerregistry.internal

import kotlinx.serialization.json.*
import org.erdtman.jcs.NumberToJSON

/** The installed canonical-json@0.2.0 protocol, including its boolean-as-object behavior. */
internal object CanonicalJson {
    fun stringify(value: JsonElement): String =
        when (value) {
            is JsonObject -> value.keys.sorted().joinToString(",", "{", "}") { quote(it) + ":" + stringify(value.getValue(it)) }
            is JsonArray -> value.joinToString(",", "[", "]") { stringify(it) }
            is JsonPrimitive ->
                when {
                    value === JsonNull -> "null"
                    value.isString -> quote(value.content)
                    value.booleanOrNull != null -> "{}"
                    else -> value.content.toDouble().let { if (it.isFinite()) NumberToJSON.serializeNumber(it) else "null" }
                }
        }

    private fun quote(value: String): String =
        buildString {
            append('"')
            for (character in value) {
                when (val code = character.code) {
                    8 -> append("\\b")
                    9 -> append("\\t")
                    10 -> append("\\n")
                    12 -> append("\\f")
                    13 -> append("\\r")
                    34 -> append("\\\"")
                    92 -> append("\\\\")
                    in 0..31, in 127..159, 173, in 0x600..0x604, 0x70f, in 0x17b4..0x17b5,
                    in 0x200c..0x200f, in 0x2028..0x202f, in 0x2060..0x206f, 0xfeff, in 0xfff0..0xffff,
                    -> {
                        append("\\u")
                        append(code.toString(16).padStart(4, '0'))
                    }
                    else -> append(character)
                }
            }
            append('"')
        }
}
