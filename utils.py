import re
import logging
from collections import OrderedDict

import requests
import json
import nltk
from nltk.tokenize import sent_tokenize
from nltk.corpus import stopwords
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

    stop_words = set()

    try:
        # Fails when no downloaded stopwords are available.
        stop_words.update(stopwords.words('english'))
    except LookupError:
        # Download stopwords since they are not available.
        nltk.download('stopwords')
        stop_words.update(stopwords.words('english'))

    regexp = re.compile('[A-Z][A-Za-z0-9-:]*')  # ? TODO: tweak
    suspects = regexp.findall(description)

    results = []

    if not suspects:
        return results

    results = [x.lower() for x in suspects if x.lower() not in stop_words]
    # get rid of duplicates, but keep order
    results = list(OrderedDict.fromkeys(results))

    return results


def get_maven_versions(ga):
    """Get all versions for given groupId:artifactId."""

    g, a = ga.split(':')
    g = g.replace('.', '/')

    filenames = {'maven-metadata.xml', 'maven-metadata-local.xml'}

    versions = set()
    ok = False
    for filename in filenames:

        url = 'http://repo1.maven.org/maven2/{g}/{a}/{f}'.format(g=g, a=a, f=filename)

        try:
            metadata_xml = etree.parse(url)
            ok = True  # We successfully downloaded the file
            version_elements = metadata_xml.findall('.//version')
            versions = versions.union({x.text for x in version_elements})
        except OSError:
            # Not both XML files have to exist, so don't freak out yet
            pass

    if not ok:
        logger.error('Unable to obtain a list of versions for {ga}'.format(ga=ga))

    return list(versions)


def get_pypi_versions(pkg_name):
    pypi_package_url = 'https://pypi.python.org/pypi/{pkg_name}/json'.format(pkg_name=pkg_name)

    response = requests.get(pypi_package_url)
    if response.status_code != 200:
        logger.error('Unable to obtain a list of versions for {pkg_name}'.format(pkg_name=pkg_name))
        return []

    return list({x for x in response.json().get('releases', {})})
