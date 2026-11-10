package org.matrix.TEESimulator.pki

import java.io.StringReader
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory

/**
 * A utility class for parsing XML content using a simplified, dot-notation path.
 *
 * This parser allows querying for XML tags and their attributes using a path string like
 * "Root.Group.Element[1].Value", which makes extracting specific data from a known XML structure
 * more convenient than manual iteration.
 *
 * @param xmlContent The raw XML string to be parsed.
 */
class XmlParser(xmlContent: String) {

    // Sanitize the XML content by removing BOMs and trimming whitespace.
    private val sanitizedXml = xmlContent.sanitize()

    /** Represents the result of a parsing operation. */
    sealed class ParseResult {
        /** Indicates a successful parse, containing the found attributes and text. */
        data class Success(val attributes: Map<String, String>) : ParseResult()

        /** Indicates a failure, containing an error message and optional cause. */
        data class Error(val message: String, val cause: Throwable? = null) : ParseResult()
    }

    /**
     * The main public method to find a node by its path and extract its data.
     *
     * @param path A dot-separated string representing the path to the desired XML tag. Indexed
     *   access is supported with brackets, e.g., `Key[0]`.
     * @return A [ParseResult] containing the attributes and text of the found node.
     */
    fun obtainPath(path: String): ParseResult {
        return try {
            val parser =
                XmlPullParserFactory.newInstance().newPullParser().apply {
                    setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false)
                    setInput(StringReader(sanitizedXml))
                }
            val tags = path.split('.').toTypedArray()
            val result = findNode(parser, tags, 0, mutableMapOf())
            ParseResult.Success(result)
        } catch (e: Exception) {
            ParseResult.Error("Failed to parse XML for path '$path'", e)
        }
    }

    /**
     * Recursively traverses the XML tree to find the node specified by the path.
     *
     * @param parser The active XmlPullParser instance.
     * @param tags The array of tag names to search for.
     * @param index The current depth in the `tags` array.
     * @param tagCounts A map to keep track of indices for tags with the same name (for `Tag[n]`
     *   support).
     * @return A map of attributes from the found node.
     */
    private fun findNode(
        parser: XmlPullParser,
        tags: Array<String>,
        index: Int,
        tagCounts: MutableMap<String, Int>,
    ): Map<String, String> {
        while (parser.next() != XmlPullParser.END_DOCUMENT) {
            if (parser.eventType != XmlPullParser.START_TAG) continue

            val currentTag = parser.name
            val (targetTagName, targetIndex) = parseTargetPath(tags[index])

            if (currentTag == targetTagName) {
                val currentTagCount = tagCounts.getOrPut(currentTag) { 0 }
                if (currentTagCount == targetIndex) {
                    // We found the correct tag at the correct index.
                    return if (index == tags.size - 1) {
                        // This is the final tag in the path, so read its attributes.
                        readAttributesAndText(parser)
                    } else {
                        // This is an intermediate tag, so recurse deeper.
                        findNode(parser, tags, index + 1, mutableMapOf())
                    }
                }
                // This is the right tag name, but not the right index, so increment and continue
                // searching.
                tagCounts[currentTag] = currentTagCount + 1
                skipCurrentElement(parser)
            } else {
                // This tag doesn't match, so skip it and its children entirely.
                skipCurrentElement(parser)
            }
        }
        throw NoSuchElementException("XML path not found: ${tags.joinToString(".")}")
    }

    /**
     * Counts the number of direct child nodes that match the final tag in a given path. For
     * example, given the path "Root.Group.Element", it will count how many <Element> tags exist
     * directly under the first <Group> tag.
     *
     * @param path A dot-separated string representing the path to the parent node.
     * @return The number of matching child nodes.
     */
    fun countNodes(path: String): Int {
        // We find the parent node first.
        val parentPath = path.substringBeforeLast('.')
        val childTagName = path.substringAfterLast('.')

        // Re-initialize the parser for a new traversal.
        val parser =
            XmlPullParserFactory.newInstance().newPullParser().apply {
                setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false)
                setInput(StringReader(sanitizedXml))
            }

        try {
            // Navigate to the parent node. This will leave the parser's cursor
            // positioned at the start of the parent's content.
            findNode(parser, parentPath.split('.').toTypedArray(), 0, mutableMapOf())

            var count = 0
            var depth = 1 // Start inside the parent node.
            while (depth > 0) {
                when (parser.next()) {
                    XmlPullParser.START_TAG -> {
                        // If we are at the immediate child level (depth == 1) and the tag name
                        // matches, increment count.
                        if (depth == 1 && parser.name == childTagName) {
                            count++
                        }
                        depth++ // Go deeper into this new tag.
                    }
                    XmlPullParser.END_TAG -> {
                        depth-- // Emerge from a tag.
                    }
                }
            }
            return count
        } catch (e: Exception) {
            // If the path doesn't exist or there's a parsing error, the count is 0.
            return 0
        }
    }

    /** Parses a path segment (e.g., "Key[1]") into its base name ("Key") and index (1). */
    private fun parseTargetPath(targetTag: String): Pair<String, Int> {
        val parts = targetTag.split('[', limit = 2)
        val tagName = parts[0]
        val index =
            if (parts.size > 1) {
                parts[1].substringBefore(']').toIntOrNull() ?: 0
            } else {
                0 // If no index is specified, we are looking for the first occurrence.
            }
        return tagName to index
    }

    /** Reads all attributes and the text content of the current XML element. */
    private fun readAttributesAndText(parser: XmlPullParser): Map<String, String> {
        val attributes = mutableMapOf<String, String>()
        for (i in 0 until parser.attributeCount) {
            attributes[parser.getAttributeName(i)] = parser.getAttributeValue(i)
        }
        // Check for text content before the next tag.
        if (parser.next() == XmlPullParser.TEXT && parser.isWhitespace.not()) {
            attributes["text"] = parser.text
        }
        return attributes
    }

    /** Advances the parser past the current element and all its children. */
    private fun skipCurrentElement(parser: XmlPullParser) {
        var depth = 1
        while (depth != 0) {
            when (parser.next()) {
                XmlPullParser.END_TAG -> depth--
                XmlPullParser.START_TAG -> depth++
            }
        }
    }

    /** Removes Byte Order Marks (BOM) and trims whitespace from the XML string. */
    private fun String.sanitize(): String {
        return this.trimStart('\uFEFF', '\uFFFE', ' ').trimEnd()
    }
}
