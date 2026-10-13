package com.universalverify.trustedissuerregistry.internal

import java.util.Locale

// Both platforms expose the same ICU API and Comparator contract. Resolve it without
// platform types in the shared JAR; Android uses its built-in ICU instead of shipping ICU4J.
private val collatorClass: Class<*> by lazy {
    try {
        Class.forName("android.icu.text.Collator")
    } catch (_: ClassNotFoundException) {
        Class.forName("com.ibm.icu.text.Collator")
    }
}

/** ICU follows the Unicode collation used by PKIjs localeCompare, including ignored characters. */
@Suppress("UNCHECKED_CAST")
internal fun nameComparator(): Comparator<String> {
    // Collators are mutable. Give each comparison its own instance for concurrent registry calls.
    val collator = collatorClass.getMethod("getInstance", Locale::class.java).invoke(null, Locale.ROOT)
    collatorClass
        .getMethod("setDecomposition", Int::class.javaPrimitiveType)
        .invoke(collator, collatorClass.getField("CANONICAL_DECOMPOSITION").getInt(null))
    return collator as Comparator<String>
}
