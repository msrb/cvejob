import re
import logging
from collections import OrderedDict

import nltk
from nltk.tokenize import sent_tokenize
from nltk.corpus import stopwords
import requests


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


def get_npm_versions(ga):
    """Get all versions for given package name."""

    url = 'https://registry.npmjs.org/{pkg_name}'.format(pkg_name=ga)

    response = requests.get(url)

    if response.status_code != 200:
        logger.error('Unable to fetch versions for package {pkg_name}'.format(pkg_name=ga))
        return []

    versions = {x for x in response.json().get('versions')}

    return list(versions)
