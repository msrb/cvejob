class MitreCVE(object):

    VERSION = '4.0'

    def __init__(self, cve_id, references, descriptions, configurations, cvss):
        self.cve_id = cve_id
        self.references = references or []
        self.descriptions = descriptions or []
        self.configurations = configurations or {}
        self.cvss = cvss

    @staticmethod
    def extract_vendor_product_version(cpe_str):
        cpe_parts = cpe_str.split(':')[2:]
        version = None
        if len(cpe_parts) >= 3:
            version = cpe_parts[2]

        return cpe_parts[0], cpe_parts[1], version

    @staticmethod
    def cpe_is_app(cpe_str):
        return cpe_str[len('cpe:/'):][0] == 'a'

    @classmethod
    def from_dict(cls, data):
        cve_dict = data.get('cve', {})

        cve_id = cve_dict.get('CVE_data_meta', {}).get('ID')
        references_data = cve_dict.get('references', {}).get('reference_data', [])
        references = [x.get('url') for x in references_data]
        descriptions_data = cve_dict.get('description', {}).get('description_data', [])
        descriptions = []
        for description in descriptions_data:
            if description.get('lang') == 'en':
                descriptions.append(description.get('value', ''))
                break

        cvss = data.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore')

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

        return cls(cve_id, references, descriptions, configurations, cvss)
