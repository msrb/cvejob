import re
import logging
from collections import OrderedDict

from nltk.tokenize import sent_tokenize
from lxml import etree


logger = logging.getLogger(__name__)


def get_first_sentence(description):
    """Get only the first sentence from the description."""
    sentences = sent_tokenize(description)
    return sentences[0] if sentences else ''


def guess_package_name(description):
    """Guess package name from given description.

    Very naive approach. Words starting with uppercase letter
    are considered to be possible package names (minus stop words).

    Returns a list of possible package names, without duplicates.
    """

    stop_words = {'in', 'the', 'a', 'an', 'the', 'when'}

    regexp = re.compile('[A-Z][A-Za-z0-9-:]*')  # ? TODO: tweak
    suspects = regexp.findall(description)

    results = []

    if not suspects:
        return results

    results = [x.lower() for x in suspects if x.lower() not in stop_words]
    # get rid of duplicates, but keep order
    results = list(OrderedDict.fromkeys(results))

    return results


def get_versions(ga):
    """Get all versions for given groupId:artifactId."""

    g, a = ga.split(':')
    g = g.replace('.', '/')
    url = 'http://repo1.maven.org/maven2/{g}/{a}/maven-metadata.xml'.format(g=g, a=a)

    versions = []
    try:
        metadata_xml = etree.parse(url)
        version_elements = metadata_xml.findall('.//version')
        versions = [x.text for x in version_elements]
    except OSError:
        logger.error('Unable to obtain a list of versions for {ga}'.format(ga=ga))
        pass

    return versions
