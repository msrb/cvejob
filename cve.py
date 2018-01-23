import json
import subprocess
from utils import guess_package_name, generate_yaml
from entry import MitreCVE


def run():
    with open('nvdcve.json') as f:
        data = json.load(f)

        for d in data.get('CVE_Items'):

            cve = MitreCVE.from_dict(d)
            print('---')
            print(cve.cve_id)

            if not cve.configurations:
                # vulnerability still under analysis, skipping...
                continue

            vendor = []
            product = []
            version = set()
            for conf in cve.configurations:
                if not MitreCVE.cpe_is_app(conf):
                    continue

                ven, prod, ver = MitreCVE.extract_vendor_product_version(conf)
                vendor.append(ven)
                product.append(prod)
                version.add(ver)
                if cve.configurations[conf]:
                    version.add(cve.configurations[conf]['version'])

            pkg_name_candidates = set()
            for description in cve.descriptions:
                names = guess_package_name(description)
                pkg_name_candidates.update(names)

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
                with open('packages') as pf:
                    for line in pf.readlines():
                        g, a, v = line.split(',')
                        if '{}:{}'.format(g, a) == ga:
                            affected = version & set(v.split())
                            if affected:
                                print('Hit!')
                                result['versions'] = list(set(v.split()))
                                winner = result
                                break

            if winner:
                generate_yaml(cve, winner, results)


if __name__ == '__main__':
    run()
