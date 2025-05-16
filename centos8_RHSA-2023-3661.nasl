#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Red Hat Security Advisory RHSA-2023:3661. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190204);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id("CVE-2023-32700");
  script_xref(name:"RHSA", value:"2023:3661");

  script_name(english:"CentOS 8 : texlive (CESA-2023:3661)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
CESA-2023:3661 advisory.

  - LuaTeX before 1.17.0 allows execution of arbitrary shell commands when compiling a TeX file obtained from
    an untrusted source. This occurs because luatex-core.lua lets the original io.popen be accessed. This also
    affects TeX Live before 2023 r66984 and MiKTeX before 23.5. (CVE-2023-32700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:3661");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:8-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-adjustbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-algorithms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-amscls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-amsfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-amsmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-anyfontsize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-anysize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-appendix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-arabxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-arphic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-attachfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-avantgar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-awesomebox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-babel-english");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-babelbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-beamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-beton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bibtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bibtopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bigfoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bookman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-booktabs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-breakurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-breqn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-capt-of");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-caption");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-carlisle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-changebar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-changepage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-charter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-chngcntr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-classpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cm-lgc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cm-super");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cmextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-cns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-collectbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-collection-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-collection-fontsrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-collection-htmlxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-collection-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-collection-latexrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-collection-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-colortbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-crop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-csquotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ctable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ctablestack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-currfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-datetime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-dvipdfmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-dvipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-dvisvgm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-eepic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-enctex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-enumitem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-environ");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-epsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-epstopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-eqparbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-eso-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-etex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-etex-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-etoolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-euenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-euler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-euro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-eurosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-extsizes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fancybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fancyhdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fancyref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fancyvrb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-filecontents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-filehook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-finstrut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fix2col");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fixlatvian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-float");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fmtcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fncychap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fontawesome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fontbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fonts-tlwg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fontspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fontware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fontwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-footmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-framed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-garuda-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-geometry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-glyphlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-graphics-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-graphics-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-gsftopk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-helvetic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyperref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyph-utf8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyphen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyphenat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifluatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifmtarg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifoddpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-iftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-jknapltx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kastrup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kerkis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-knuth-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-knuth-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-koma-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-l3experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-l3kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-l3packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lastpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latex2man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lettrine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-linegoal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lineno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-listings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lm-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ltabptch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ltxmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lua-alt-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lualatex-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lualibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luaotfload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luatex85");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luatexbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-makecmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-makeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-manfnt-font");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-marginnote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-marvosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mathpazo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mathtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mdwtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-memoir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-metafont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-metalogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mflogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mflogo-font");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mfnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mfware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-microtype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mnsymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mparhack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mptopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-multido");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-multirow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-natbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ncctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ncntrsbk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-needspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-norasi-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ntgclass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-oberdiek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-overpic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-palatino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-paralist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-parskip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-passivetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdfpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pgf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-philokalia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-placeins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-polyglossia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-powerdot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-preprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-psfrag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pslatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-psnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pspicture");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-arrow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-blur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-coil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-fill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-grad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-plot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-slpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pst-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pstricks-add");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ptext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pxfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-qstest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-rcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-realscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-rsfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sansmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sauerj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-scheme-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sectsty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-seminar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sepnum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-setspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-showexpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-soul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-stmaryrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-subfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-subfigure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-svn-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-t2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tabu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tabulary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex-gyre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex-gyre-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex-ini-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex4ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-common-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-docindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-msg-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive.infra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-textcase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-textpos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-threeparttable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-thumbpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-times");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-titlesec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-titling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tocloft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-translator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-trimspaces");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-txfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-type1cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-typehtml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ucharclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-uhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ulem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-underscore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-unicode-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-unicode-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-unisugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-updmap-map");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-upquote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-utopia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-varwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wadalab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-was");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wasy2-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wasysym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wrapfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xcolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xecjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xecolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xecyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xepersian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xesearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xetex-itrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xetex-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xetex-tibetan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xetexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xetexfontinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xifthen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xkeyval");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xltxtra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xmltex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xmltexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xtab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xunicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-zapfchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-zapfding");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if ('CentOS Stream' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS 8-Stream');
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'CentOS 8.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2023-32700');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for CESA-2023:3661');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

var pkgs = [
    {'reference':'texlive-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-adjustbox-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-adjustbox-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ae-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ae-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-algorithms-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-algorithms-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amscls-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amscls-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amsfonts-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amsfonts-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amsmath-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-amsmath-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-anyfontsize-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-anyfontsize-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-anysize-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-anysize-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-appendix-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-appendix-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-arabxetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-arabxetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-arphic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-arphic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-attachfile-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-attachfile-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-avantgar-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-avantgar-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-awesomebox-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-awesomebox-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babel-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babel-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babel-english-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babel-english-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babelbib-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-babelbib-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-base-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-base-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-beamer-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-beamer-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bera-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bera-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-beton-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-beton-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bibtex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bibtex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bibtopic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bibtopic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bidi-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bidi-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bigfoot-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bigfoot-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bookman-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-bookman-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-booktabs-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-booktabs-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-breakurl-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-breakurl-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-breqn-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-breqn-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-capt-of-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-capt-of-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-caption-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-caption-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-carlisle-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-carlisle-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-changebar-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-changebar-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-changepage-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-changepage-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-charter-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-charter-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-chngcntr-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-chngcntr-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cite-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cite-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cjk-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cjk-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-classpack-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-classpack-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-lgc-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-lgc-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-super-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cm-super-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cmap-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cmap-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cmextra-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cmextra-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cns-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-cns-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collectbox-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collectbox-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-basic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-basic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-fontsrecommended-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-fontsrecommended-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-htmlxml-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-htmlxml-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-latex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-latex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-latexrecommended-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-latexrecommended-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-xetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-collection-xetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-colortbl-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-colortbl-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-context-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-context-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-courier-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-courier-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-crop-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-crop-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-csquotes-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-csquotes-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ctable-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ctable-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ctablestack-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ctablestack-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-currfile-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-currfile-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-datetime-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-datetime-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipdfmx-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipng-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvipng-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvips-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvips-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvisvgm-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-dvisvgm-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ec-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ec-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eepic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eepic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-enctex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-enctex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-enumitem-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-enumitem-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-environ-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-environ-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-epsf-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-epsf-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-epstopdf-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-epstopdf-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eqparbox-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eqparbox-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eso-pic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eso-pic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etex-pkg-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etex-pkg-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etoolbox-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-etoolbox-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euenc-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euenc-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euler-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euler-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euro-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-euro-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eurosym-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-eurosym-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-extsizes-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-extsizes-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancybox-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancybox-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyhdr-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyhdr-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyref-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyref-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyvrb-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fancyvrb-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-filecontents-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-filecontents-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-filehook-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-filehook-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-finstrut-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-finstrut-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fix2col-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fix2col-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fixlatvian-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fixlatvian-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-float-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-float-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fmtcount-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fmtcount-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fncychap-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fncychap-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontawesome-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontawesome-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontbook-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontbook-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fonts-tlwg-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fonts-tlwg-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontspec-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontspec-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontware-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontware-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontwrap-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fontwrap-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-footmisc-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-footmisc-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fp-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fp-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fpl-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-fpl-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-framed-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-framed-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-garuda-c90-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-garuda-c90-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-geometry-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-geometry-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-glyphlist-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-glyphlist-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-cfg-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-cfg-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-def-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-graphics-def-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-gsftopk-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-gsftopk-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-helvetic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-helvetic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyperref-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyperref-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyph-utf8-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyph-utf8-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyphen-base-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyphen-base-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyphenat-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-hyphenat-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifluatex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifluatex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifmtarg-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifmtarg-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifoddpage-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifoddpage-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-iftex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-iftex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifxetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ifxetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-import-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-import-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-index-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-index-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-jadetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-jadetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-jknapltx-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-jknapltx-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kastrup-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kastrup-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kerkis-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kerkis-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-knuth-lib-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-knuth-lib-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-knuth-local-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-knuth-local-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-koma-script-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-koma-script-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kpathsea-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-kpathsea-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3experimental-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3experimental-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3kernel-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3kernel-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3packages-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-l3packages-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lastpage-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lastpage-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex-fonts-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex-fonts-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex2man-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latex2man-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latexconfig-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-latexconfig-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lettrine-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lettrine-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-devel-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lib-devel-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-linegoal-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-linegoal-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lineno-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lineno-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-listings-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-listings-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lm-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lm-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lm-math-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lm-math-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ltabptch-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ltabptch-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ltxmisc-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ltxmisc-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lua-alt-getopt-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lua-alt-getopt-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lualatex-math-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lualatex-math-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lualibs-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-lualibs-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luaotfload-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luaotfload-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatex85-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatex85-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatexbase-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-luatexbase-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-makecmds-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-makecmds-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-makeindex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-makeindex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-manfnt-font-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-manfnt-font-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-marginnote-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-marginnote-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-marvosym-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-marvosym-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathpazo-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathpazo-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathspec-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathspec-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathtools-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mathtools-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mdwtools-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mdwtools-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-memoir-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-memoir-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metafont-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metafont-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metalogo-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metalogo-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metapost-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-metapost-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mflogo-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mflogo-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mflogo-font-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mflogo-font-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mfnfss-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mfnfss-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mfware-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mfware-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-microtype-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-microtype-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mnsymbol-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mnsymbol-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mparhack-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mparhack-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mptopdf-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-mptopdf-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ms-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ms-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-multido-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-multido-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-multirow-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-multirow-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-natbib-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-natbib-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ncctools-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ncctools-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ncntrsbk-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ncntrsbk-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-needspace-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-needspace-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-norasi-c90-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-norasi-c90-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ntgclass-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ntgclass-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-oberdiek-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-oberdiek-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-overpic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-overpic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-palatino-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-palatino-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-paralist-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-paralist-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-parallel-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-parallel-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-parskip-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-parskip-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-passivetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-passivetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pdfpages-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pdfpages-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pdftex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pdftex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pgf-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pgf-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-philokalia-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-philokalia-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-placeins-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-placeins-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-plain-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-plain-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-polyglossia-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-polyglossia-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-powerdot-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-powerdot-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-preprint-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-preprint-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-psfrag-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-psfrag-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pslatex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pslatex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-psnfss-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-psnfss-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pspicture-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pspicture-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-3d-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-3d-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-arrow-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-arrow-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-blur-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-blur-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-coil-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-coil-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-eps-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-eps-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-fill-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-fill-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-grad-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-grad-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-math-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-math-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-node-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-node-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-plot-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-plot-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-slpe-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-slpe-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-text-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-text-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-tools-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-tools-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-tree-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pst-tree-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pstricks-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pstricks-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pstricks-add-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pstricks-add-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ptext-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ptext-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pxfonts-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-pxfonts-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-qstest-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-qstest-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-rcs-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-rcs-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-realscripts-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-realscripts-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-rsfs-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-rsfs-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sansmath-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sansmath-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sauerj-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sauerj-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-scheme-basic-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-scheme-basic-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-section-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-section-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sectsty-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sectsty-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-seminar-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-seminar-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sepnum-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-sepnum-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-setspace-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-setspace-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-showexpl-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-showexpl-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-soul-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-soul-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-stmaryrd-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-stmaryrd-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-subfig-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-subfig-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-subfigure-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-subfigure-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-svn-prov-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-svn-prov-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-symbol-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-symbol-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-t2-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-t2-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tabu-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tabu-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tabulary-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tabulary-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-gyre-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-gyre-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-gyre-math-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-gyre-math-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-ini-files-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex-ini-files-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex4ht-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tex4ht-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texconfig-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texconfig-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-common-doc-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-common-doc-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-docindex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-docindex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-en-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-en-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-msg-translations-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-msg-translations-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-scripts-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive-scripts-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive.infra-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-texlive.infra-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-textcase-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-textcase-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-textpos-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-textpos-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-threeparttable-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-threeparttable-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-thumbpdf-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-thumbpdf-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-times-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-times-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tipa-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tipa-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-titlesec-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-titlesec-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-titling-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-titling-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tocloft-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tocloft-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tools-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-tools-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-translator-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-translator-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-trimspaces-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-trimspaces-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-txfonts-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-txfonts-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-type1cm-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-type1cm-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-typehtml-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-typehtml-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ucharclasses-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ucharclasses-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ucs-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ucs-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-uhc-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-uhc-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ulem-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-ulem-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-underscore-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-underscore-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unicode-data-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unicode-data-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unicode-math-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unicode-math-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unisugar-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-unisugar-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-updmap-map-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-updmap-map-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-upquote-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-upquote-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-url-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-url-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-utopia-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-utopia-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-varwidth-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-varwidth-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wadalab-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wadalab-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-was-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-was-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasy-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasy-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasy2-ps-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasy2-ps-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasysym-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wasysym-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wrapfig-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-wrapfig-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xcolor-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xcolor-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xdvi-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xdvi-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecjk-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecjk-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecolor-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecolor-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecyr-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xecyr-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xeindex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xeindex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xepersian-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xepersian-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xesearch-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xesearch-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-itrans-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-itrans-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-pstricks-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-pstricks-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-tibetan-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetex-tibetan-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetexconfig-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetexconfig-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetexfontinfo-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xetexfontinfo-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xifthen-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xifthen-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xkeyval-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xkeyval-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xltxtra-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xltxtra-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xmltex-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xmltex-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xmltexconfig-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xmltexconfig-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xstring-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xstring-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xtab-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xtab-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xunicode-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-xunicode-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-zapfchan-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-zapfchan-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-zapfding-20180414-29.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'},
    {'reference':'texlive-zapfding-20180414-29.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'7'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'texlive / texlive-adjustbox / texlive-ae / texlive-algorithms / etc');
}
