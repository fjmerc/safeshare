#!/bin/sh
# Make the qpdf variants of sample.pdf for tests/js/pdf-metadata.test.js:
# object streams with a cross-reference stream (Info and the annotation end
# up compressed inside an object stream), and a linearized copy. Needs qpdf.
#
#   sh tests/js/fixtures/make_pdf_variants.sh
set -e
cd "$(dirname "$0")"
qpdf --object-streams=generate --compress-streams=y sample.pdf sample-objstm.pdf
qpdf --linearize sample.pdf sample-linear.pdf
qpdf --encrypt "" owner 256 -- sample.pdf sample-encrypted.pdf
