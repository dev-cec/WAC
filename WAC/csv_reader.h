/*! \file
 *  \brief CSV READING (RFC 4180), for the CCADB report --update-trust
 *         downloads.
 *
 *  WHY THIS MODULE EXISTS. The Common CA Database publishes every
 *  certificate authority of the root programs — Microsoft's among them —, its
 *  capabilities and the revocation lists it issues, as one CSV report. Its
 *  fields hold commas, quotes and line breaks: a split on commas and lines
 *  would shift the columns silently, and hand one authority's revocation list
 *  to another.
 *
 *  The report comes from the network: a quote left open, or a record with
 *  fewer fields than the header, is refused rather than guessed.
 *
 *  Portable C++: checked against Python's csv module (see csv_reader_test).
 */
#pragma once

#include <string>
#include <vector>

/*! A CSV text, read into records of fields.
 *  @param text the text (UTF-8, as downloaded; a leading byte order mark is skipped)
 *  @param records receives the records, the header first
 *  @param reason why the text is refused
 *  @return false if a quote is left open, or a record has not as many fields
 *          as the header */
bool CsvRead(const std::string& text, std::vector<std::vector<std::string>>& records, std::string& reason);
