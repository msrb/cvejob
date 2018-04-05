import os


def generate_yaml(cve, winner, results):
    template = """---
cve: {cve_id}
title: CVE in {pkg_name}
description: >
    {desc}
cvss_v2: {cvss}
references:
    - {refs}
affected:
    - name: {pkg}
      version:
        - "{v}"
      fixedin:
        - "{fixed_in}"
# Additional information:
#  configurations:
{configurations}
#
# All available versions:
#versions
#
# Other possible package names:
{others}
"""

    _, year, cid = cve.cve_id.split('-')
    try:
        os.makedirs('database/java/{y}'.format(y=year))
    except FileExistsError:
        pass

    with open('database/java/{y}/{id}.yaml'.format(y=year, id=cid), 'w') as f:
        pkg = winner['ga']
        refs = '    - '.join([x + '\n' for x in cve.references])
        description = cve.description

        confs = []
        for conf in cve.configurations:
            conf_str = '#    - {cpe}'.format(cpe=conf)
            v = cve.configurations[conf]
            if v and v['version']:
                conf_str += " " + v['version'] + " (" + v['kind'] + ")"
            confs.append(conf_str)

        others = []
        for result in results:
            other_str = "# " + result['score'] + ' ' + result['ga']
            others.append(other_str)

        data = template.format(cve_id=cve.cve_id.split('-', 1)[1], pkg_name=winner['ga'], cvss=cve.cvss,
                               desc=description, pkg=pkg, v='!FIXME!',
                               refs=refs, fixed_in='!FIXME!', configurations='\n'.join(confs),
                               others='\n'.join(others))
        f.write(data)
