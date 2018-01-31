"""Handle cve entries from NVD database"""

import datetime

from collections import OrderedDict


class CVE(object):
    """CVE object holding relevant atributes about the given cve"""
    # TODO: think about inheriting from dict or DataFrame for future usage

    VERSION = '4.0'

    def __init__(self, cve_id: str, references: list,
                 description: str, configurations: dict,
                 cvss, published_date: str, last_modified_date: str):

        # TODO group_id, artifact_id
        self.cve_id = cve_id
        self.references = references or []
        self.description = description or ""
        self.configurations = configurations or {}
        self.cvss = cvss
        self.published_date = published_date
        self.last_modified_date = last_modified_date

        self.dct = self._construct_dct()

    def __str__(self):
        return self.dct.__str__()  # TODO maybe dump to json string?

    def _construct_dct(self):
        """Construct dictionary from self attributes by NVD schema"""
        dct = OrderedDict()

        dct['cve_id'] = self.cve_id
        dct['references'] = self.references
        dct['description'] = self.description
        dct['configurations'] = self.configurations
        dct['cvss'] = self.cvss
        dct['publishedDate'] = self.published_date
        dct['lastModifiedDate'] = self.last_modified_date

        return dct

    @classmethod
    def from_dict(cls, data):

        date_format = '%Y-%m-%dT%H:%MZ'
        published_date = datetime.datetime.strptime(data.get('publishedDate'), date_format)
        last_modified_date = datetime.datetime.strptime(data.get('lastModifiedDate'), date_format)

        cve_dict = data.get('cve', {})

        # CVE ID
        cve_id = cve_dict.get('CVE_data_meta', {}).get('ID')

        # References  # TODO parse for bad url data: like `a=commit;h=....`
        references_data = cve_dict.get('references', {}).get('reference_data', [])
        references = [x.get('url') for x in references_data]

        # English description
        description_data = cve_dict.get('description', {}).get('description_data', [])
        description = ""
        for lang_description in description_data:
            if lang_description.get('lang') == 'en':
                description = lang_description.get('value', '')
                break

        # CVSSv2
        cvss = data.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')

        # Configurations  # TODO create better configurations dict - better parsing, keys, etc..
        configurations = {}
        nodes = data.get('configurations', {}).get('nodes', [])
        for node in nodes:
            cpes = node.get('cpe', [])
            for cpe in cpes:
                if cpe.get('vulnerable', True):
                    cpe_str = cpe.get('cpe22Uri')
                    if cpe_str:
                        configurations[cpe_str] = None
                    if cpe.get('versionEndIncluding') is not None:
                        configurations[cpe_str] = {'version': cpe.get('versionEndIncluding'),
                                                   'kind': 'including'}
                    elif cpe.get('versionEndExcluding') is not None:
                        configurations[cpe_str] = {'version': cpe.get('versionEndExcluding'),
                                                   'kind': 'excluding'}

        return cls(cve_id=cve_id,
                   references=references,
                   description=description,
                   configurations=configurations,
                   cvss=cvss,
                   published_date=published_date,
                   last_modified_date=last_modified_date)


def cpe_is_app(cpe_str):
    """Return True if cpe is of application entry type"""
    return cpe_str[len('cpe:/'):][0] == 'a'


def extract_vendor_product_version(cpe_str):
    cpe_parts = cpe_str.split(':')[2:]
    version = None
    if len(cpe_parts) >= 3:
        version = cpe_parts[2]

    return cpe_parts[0], cpe_parts[1], version


def extract_entries_by_type(cve_items: list, entry_type: str = '') -> list:
    """
    Extract entries from a list of cve dictionaries by specific entry type

    :param cve_items: list of cve dictionary items
    :param entry_type: str, {application, hardware} or abbreviation of them (default '')

    :returns: list of cve entries matching the given entry type
    """

    # TODO: think about taking file / json instead of list of cve_items

    cve_entries = list()
    for entry in cve_items:
        nodes = entry.get('configurations', {}).get('nodes', [])
        for node in nodes:
            cpes = node.get('cpe', [])
            for cpe in cpes:
                if cpe.get('vulnerable', True):
                    cpe_str = cpe.get('cpe22Uri')
                    cpe_type = "cpe:/{entry_type}".format(entry_type=entry_type[:1] or '')
                    if cpe_str.startswith(cpe_type):
                        cve = CVE.from_dict(entry)
                        cve_entries.append(cve)

    return cve_entries

