import os
import json
import subprocess
import datetime
import logging
from collections import OrderedDict

from utils import get_first_sentence, guess_package_name, get_npm_versions
from output import generate_yaml
from cve import CVE, cpe_is_app, extract_vendor_product_version


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('cvejob')


def is_older_than(cve, days):
    """Check if the CVE was last modified no longer than `days` ago."""
    now = datetime.datetime.now()
    age = now.date() - cve.last_modified_date.date()
    return age.days > days


def get_vendor_product_versions(cve):
    """Extract vendor, product and versions."""
    vendor = []
    product = []
    cpe_versions = set()
    for conf in cve.configurations:
        if not cpe_is_app(conf):
            # not an app, skipping...
            continue

        ven, prod, ver = extract_vendor_product_version(conf)
        vendor.append(ven)
        product.append(prod)
        if ver:
            cpe_versions.add(ver)
        if cve.configurations[conf]:
            cpe_versions.add(cve.configurations[conf]['version'])

    return vendor, product, cpe_versions


def get_package_name_candidates(cve):
    """Try to identify possible package names in the CVE's description."""
    pkg_name_candidates = set()
    first_sentence = get_first_sentence(cve.description)
    names = guess_package_name(first_sentence)
    pkg_name_candidates.update(set(names))
    return pkg_name_candidates


def construct_lucene_query(vendor, product):
    """Construct lucene query for given vendor and product."""
    query_template = 'product:( {product} )  AND  vendor:( {vendor} )'
    p = ' '.join(product).replace(':', ' ')
    v = ' '.join(vendor).replace(':', ' ')
    query = query_template.format(product=p, vendor=v)

    return query


def run_cpe2pkg(query):
    """Run cpe2pkg tool with given query."""
    cpe2pkg_output = subprocess.check_output('java -jar target/cpe2pkg.jar "' + query + '"',
                                             shell=True,
                                             universal_newlines=True)
    cpe2pkg_lines = cpe2pkg_output.split('\n')
    results = []

    for line in cpe2pkg_lines:
        if not line:
            continue
        score, ga = line.split()
        results.append({'ga': ga[len('npm:'):], 'score': score})

    if results:
        logger.info('Found {n} suspects'.format(n=len(results)))

    return results


# TODO: turn into proper CLI app
def run():

    cherrypicked = os.environ.get('CVE_ID', '').strip()

    # TODO: make configurable
    with open('nvdcve.json') as f:
        data = json.load(f)

        for d in data.get('CVE_Items'):

            cve = CVE.from_dict(d)
            logger.info('---')
            logger.info('Found {cve}'.format(cve=cve.cve_id))

            age = int(os.environ.get('CVEJOB_AGE', 1))

            if cherrypicked:
                if cve.cve_id != cherrypicked:
                    continue
            elif is_older_than(cve, age):
                logger.info('The CVE is too old, skipping...')
                continue

            if not cve.configurations:
                logger.info('The vulnerability is still under analysis, skipping...')
                continue

            vendor, product, cpe_versions = get_vendor_product_versions(cve)
            # pkg_name_candidates = get_package_name_candidates(cve)
            pkg_name_candidates = set()

            vendor = ['npm']
            product = list(OrderedDict.fromkeys(product + list(pkg_name_candidates)))

            if not product or not vendor:
                continue

            query = construct_lucene_query(vendor, product)
            logger.info('Query: {q}'.format(q=query))

            results = run_cpe2pkg(query)

            if cpe_versions:
                # try to exclude false positives
                # winner is simply the first match we found
                winner = None
                for result in results:
                    ga = result['ga']

                    # check if at least one version mentioned in the CVE exists for given groupId:artifactId;
                    # if not, this is a false positive
                    upstream_versions = get_npm_versions(ga)
                    logger.info('Checking {ga} (upstream: {v}; cpe: {cv}'.format(ga=ga,
                                                                                 v=upstream_versions,
                                                                                 cv=cpe_versions))
                    if cpe_versions & set(upstream_versions):
                        # exact match, great!
                        winner = result

                    if winner:
                        logger.info('Hit for {ga}'.format(ga=ga))
                        result['versions'] = upstream_versions
                        break

                if winner:
                    generate_yaml(cve, winner, results)


if __name__ == '__main__':
    run()
