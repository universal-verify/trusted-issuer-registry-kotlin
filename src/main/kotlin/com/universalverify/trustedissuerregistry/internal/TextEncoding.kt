package com.universalverify.trustedissuerregistry.internal

import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction

/** Match TextEncoder's U+FFFD replacement for unpaired UTF-16 surrogates. */
internal fun encodeUtf8(value: String): ByteArray {
    val encoder =
        Charsets.UTF_8
            .newEncoder()
            .onMalformedInput(CodingErrorAction.REPLACE)
            .onUnmappableCharacter(CodingErrorAction.REPLACE)
            .replaceWith(byteArrayOf(0xef.toByte(), 0xbf.toByte(), 0xbd.toByte()))
    val encoded = encoder.encode(CharBuffer.wrap(value))
    return ByteArray(encoded.remaining()).also { encoded.get(it) }
}

/** TextDecoder strips a leading UTF-8 BOM before JSON parsing. */
internal fun decodeJsonText(bytes: ByteArray): String = bytes.toString(Charsets.UTF_8).removePrefix("\ufeff")
