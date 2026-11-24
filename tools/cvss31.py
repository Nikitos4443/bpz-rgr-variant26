#!/usr/bin/env python3
"""Мінімальний калькулятор базової оцінки CVSS v3.1."""
import sys, math

AV={'N':0.85,'A':0.62,'L':0.55,'P':0.2}
AC={'L':0.77,'H':0.44}
UI={'N':0.85,'R':0.62}
PR_U={'N':0.85,'L':0.62,'H':0.27}
PR_C={'N':0.85,'L':0.68,'H':0.50}
CIA={'H':0.56,'L':0.22,'N':0.0}

def rc(x): return math.ceil(x*10)/10

def score(vec):
    m=dict(p.split(':') for p in vec.replace('CVSS:3.1/','').split('/'))
    scope_changed = m['S']=='C'
    pr = (PR_C if scope_changed else PR_U)[m['PR']]
    iss = 1-((1-CIA[m['C']])*(1-CIA[m['I']])*(1-CIA[m['A']]))
    if scope_changed:
        impact = 7.52*(iss-0.029)-3.25*((iss-0.02)**15)
    else:
        impact = 6.42*iss
    expl = 8.22*AV[m['AV']]*AC[m['AC']]*pr*UI[m['UI']]
    if impact<=0: return 0.0, round(impact,2), round(expl,1)
    if scope_changed:
        base = min(1.08*(impact+expl),10)
    else:
        base = min(impact+expl,10)
    return rc(base), round(impact,1), round(expl,1)

vectors = {
 'R-01 IDOR basket':      'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
 'R-02 Product tamper':   'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
 'R-03 RateLimit bypass': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
 'R-04 User list expose': 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
 'R-05 Forged review':    'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N',
 'R-06 BasketItem IDOR':  'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N',
 'R-07 Forged feedback':  'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N',
 'R-08 Admin UI access':  'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N',
 'R-09 Vuln deps (JWT)':  'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
 'R-10 Admin reg (role)': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N',
}
def sev(b):
    return 'Critical' if b>=9 else 'High' if b>=7 else 'Medium' if b>=4 else 'Low' if b>0 else 'None'
for k,v in vectors.items():
    b,i,e=score(v)
    print(f"{k:24s} {b:>4}  {sev(b):8s}  {v}")
