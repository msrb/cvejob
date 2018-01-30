import json
import subprocess
import datetime
from utils import get_first_sentence, guess_package_name, get_versions
from output import generate_yaml
from cve import CVE, cpe_is_app, extract_vendor_product_version


def run():
    with open('nvdcve.json') as f:
        data = json.load(f)

        for d in data.get('CVE_Items'):

            cve = CVE.from_dict(d)
            print('---')
            print(cve.cve_id)

            now = datetime.datetime.now()
            age = now.date() - cve.last_modified_date.date()
            if not cve.last_modified_date or age.days >= 3:
                # not modified today/yesterday, skipping...
                continue

            if not cve.configurations:
                # vulnerability still under analysis, skipping...
                continue

            vendor = []
            product = []
            version = set()
            for conf in cve.configurations:
                if not cpe_is_app(conf):
                    continue

                ven, prod, ver = extract_vendor_product_version(conf)
                vendor.append(ven)
                product.append(prod)
                version.add(ver)
                if cve.configurations[conf]:
                    version.add(cve.configurations[conf]['version'])

            pkg_name_candidates = set()
            for description in cve.descriptions:
                first_sentence = get_first_sentence(description)
                names = guess_package_name(first_sentence)
                pkg_name_candidates.update(set(names))

            product += list(pkg_name_candidates)
            if not product or not vendor:
                continue

            query_template = 'product:( {product} )  AND  vendor:( {vendor} )'
            p = ' '.join(product).replace(':', ' ')
            v = ' '.join(vendor).replace(':', ' ')
            query = query_template.format(product=p, vendor=v)
            print('Query: ' + query)

            cpe2pkg_output = subprocess.check_output('java -jar target/cpe2pkg.jar "' + query + '"',
                                                     shell=True,
                                                     universal_newlines=True)
            cpe2pkg_lines = cpe2pkg_output.split('\n')
            results = []

            for line in cpe2pkg_lines:
                if not line:
                    continue
                score, ga = line.split()
                results.append({'ga': ga, 'score': score})

            winner = None
            for result in results:
                ga = result['ga']
                upstream_versions = get_versions(ga)
                affected = version & set(upstream_versions)
                if affected:
                    print('Hit!')
                    result['versions'] = upstream_versions
                    winner = result
                    break

            if winner:
                generate_yaml(cve, winner, results)


if __name__ == '__main__':
    run()
