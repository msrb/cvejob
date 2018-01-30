import re
from collections import OrderedDict

from nltk.tokenize import sent_tokenize


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
