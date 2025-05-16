#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(191402);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id("CVE-2023-32700");

  script_name(english:"CentOS 9 : texlive-20200406-26.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing a security update for texlive.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
texlive-20200406-26.el9 build changelog.

  - LuaTeX before 1.17.0 allows execution of arbitrary shell commands when compiling a TeX file obtained from
    an untrusted source. This occurs because luatex-core.lua lets the original io.popen be accessed. This also
    affects TeX Live before 2023 r66984 and MiKTeX before 23.5. (CVE-2023-32700)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=33276");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream texlive package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32700");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-acronym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-adjustbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-algorithms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-alphalph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-amscls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-amsfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-amsmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-anyfontsize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-anysize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-appendix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-arabxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-arphic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-atbegshi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-attachfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-attachfile2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-atveryend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-auxhook");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bigintcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bitset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bookman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-bookmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-booktabs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-breakurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-breqn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-capt-of");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-caption");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-carlisle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-catchfile");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-colorprofiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-colortbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-crop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-csquotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ctable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ctablestack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-currfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-datetime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-dehyph");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-epstopdf-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-eqparbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-eso-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-etex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-etex-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-etexcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-etoc");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-footnotehyper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-fpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-framed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-garuda-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-geometry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-gettitlestring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-glyphlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-gnu-freefont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-graphics-cfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-graphics-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-grfext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-grffile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-gsftopk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hanging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-helvetic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hobsub");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hologo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hycolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyperref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyph-utf8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyphen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyphenat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-hyphenex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifmtarg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifoddpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ifplatform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-iftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-infwarerr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-intcalc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-jknapltx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kastrup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kerkis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-knuth-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-knuth-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-koma-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kvdefinekeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kvoptions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-kvsetkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-l3backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-l3experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-l3kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-l3packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lastpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latex2man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latexbug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-letltxmacro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lettrine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-linegoal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lineno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-listings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-listofitems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lm-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ltabptch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ltxcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ltxmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lua-alt-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luahbtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luajittex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lualatex-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lualibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luaotfload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luatex85");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-luatexbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-lwarp");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-minitoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mnsymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-modes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mparhack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-mptopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-multido");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-multirow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-natbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ncctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ncntrsbk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-needspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-newfloat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-newunicodechar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-norasi-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-notoccite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ntgclass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-oberdiek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-obsolete");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-overpic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-palatino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-paralist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-parskip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-passivetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdfcolmk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdfescape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdflscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdfpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pdftexcmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-pgf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-philokalia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-placeins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-polyglossia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-powerdot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-preprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-preview");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ragged2e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-rcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-realscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-refcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-relsize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-rerunfilecheck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-rsfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sansmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sansmathaccent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sauerj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-scheme-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sectsty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-seminar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sepnum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-setspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-sfmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-showexpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-soul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-stackengine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-stmaryrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-stringenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-subfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-subfigure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-svn-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-t2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tabu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tabulary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex-gyre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex-gyre-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex-ini-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-tex4ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-common-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-docindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-msg-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-scripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-texlive-scripts-extra");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ucharcat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ucharclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-uhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-ulem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-underscore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-unicode-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-unicode-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-uniquecounter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-unisugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-updmap-map");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-upquote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-utopia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-varwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wadalab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-was");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-wasy-type1");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xpatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xtab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xunicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-zapfchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-zapfding");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-zref");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'texlive-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-acronym-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-adjustbox-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ae-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-algorithms-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-alphalph-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amscls-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amsfonts-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-amsmath-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-anyfontsize-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-anysize-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-appendix-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-arabxetex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-arphic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-atbegshi-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-attachfile-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-attachfile2-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-atveryend-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-auxhook-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-avantgar-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-awesomebox-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-babel-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-babel-english-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-babelbib-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-base-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-beamer-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bera-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-beton-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bibtex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bibtopic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bidi-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bigfoot-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bigintcalc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bitset-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bookman-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-bookmark-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-booktabs-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-breakurl-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-breqn-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-capt-of-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-caption-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-carlisle-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-catchfile-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-changebar-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-changepage-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-charter-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-chngcntr-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cite-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cjk-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-classpack-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cm-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cm-lgc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cm-super-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cmap-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cmextra-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-cns-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collectbox-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-basic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-fontsrecommended-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-htmlxml-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-latex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-latexrecommended-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-collection-xetex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-colorprofiles-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-colortbl-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-context-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-courier-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-crop-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-csquotes-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ctable-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ctablestack-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-currfile-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-datetime-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dehyph-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipdfmx-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvipng-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvips-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-dvisvgm-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ec-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eepic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-enctex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-enumitem-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-environ-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-epsf-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-epstopdf-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-epstopdf-pkg-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eqparbox-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eso-pic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etex-pkg-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etexcmds-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-etoolbox-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-euenc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-euler-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-euro-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-eurosym-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-extsizes-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancybox-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancyhdr-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancyref-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fancyvrb-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-filecontents-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-filehook-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-finstrut-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fix2col-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fixlatvian-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-float-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fmtcount-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fncychap-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontawesome-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontbook-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fonts-tlwg-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontspec-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontware-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fontwrap-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-footmisc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-footnotehyper-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fp-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-fpl-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-framed-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-garuda-c90-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-geometry-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gettitlestring-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-glyphlist-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gnu-freefont-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-cfg-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-graphics-def-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-grfext-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-grffile-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-gsftopk-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hanging-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-helvetic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hobsub-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hologo-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hycolor-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyperref-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyph-utf8-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyphen-base-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyphenat-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-hyphenex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifmtarg-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifoddpage-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ifplatform-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-iftex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-import-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-index-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-infwarerr-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-intcalc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-jadetex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-jknapltx-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kastrup-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kerkis-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-knuth-lib-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-knuth-local-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-koma-script-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kpathsea-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvdefinekeys-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvoptions-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-kvsetkeys-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3backend-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3experimental-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3kernel-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-l3packages-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lastpage-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latex-fonts-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latex2man-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latexbug-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-latexconfig-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-letltxmacro-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lettrine-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lib-devel-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-linegoal-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lineno-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-listings-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-listofitems-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lm-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lm-math-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltabptch-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltxcmds-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ltxmisc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lua-alt-getopt-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luahbtex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luajittex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lualatex-math-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lualibs-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luaotfload-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luatex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luatex85-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-luatexbase-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-lwarp-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-makecmds-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-makeindex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-manfnt-font-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-marginnote-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-marvosym-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mathpazo-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mathspec-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mathtools-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mdwtools-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-memoir-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metafont-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metalogo-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-metapost-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mflogo-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mflogo-font-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mfnfss-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mfware-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-microtype-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-minitoc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mnsymbol-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-modes-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mparhack-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-mptopdf-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ms-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-multido-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-multirow-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-natbib-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ncctools-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ncntrsbk-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-needspace-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-newfloat-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-newunicodechar-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-norasi-c90-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-notoccite-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ntgclass-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-oberdiek-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-obsolete-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-overpic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-palatino-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-paralist-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-parallel-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-parskip-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-passivetex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfcolmk-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfescape-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdflscape-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdfpages-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdftex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pdftexcmds-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pgf-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-philokalia-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-placeins-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-plain-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-polyglossia-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-powerdot-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-preprint-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-preview-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-psfrag-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pslatex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-psnfss-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pspicture-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-3d-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-arrow-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-blur-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-coil-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-eps-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-fill-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-grad-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-math-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-node-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-plot-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-slpe-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-text-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-tools-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pst-tree-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pstricks-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pstricks-add-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ptext-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-pxfonts-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-qstest-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ragged2e-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rcs-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-realscripts-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-refcount-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-relsize-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rerunfilecheck-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-rsfs-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sansmath-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sansmathaccent-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sauerj-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-scheme-basic-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-section-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sectsty-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-seminar-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sepnum-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-setspace-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-sfmath-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-showexpl-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-soul-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stackengine-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stmaryrd-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-stringenc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-subfig-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-subfigure-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-svn-prov-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-symbol-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-t2-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tabu-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tabulary-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-gyre-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-gyre-math-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex-ini-files-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tex4ht-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-common-doc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-docindex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-en-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-msg-translations-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-scripts-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive-scripts-extra-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-texlive.infra-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-textcase-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-textpos-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-threeparttable-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-thumbpdf-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-times-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tipa-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-titlesec-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-titling-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tocloft-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-tools-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-translator-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-trimspaces-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-txfonts-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-type1cm-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-typehtml-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucharcat-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucharclasses-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ucs-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-uhc-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-ulem-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-underscore-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unicode-data-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unicode-math-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-uniquecounter-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-unisugar-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-updmap-map-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-upquote-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-url-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-utopia-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-varwidth-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wadalab-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-was-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasy-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasy-type1-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wasysym-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-wrapfig-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xcolor-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xdvi-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xecjk-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xecolor-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xecyr-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xeindex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xepersian-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xesearch-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-itrans-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-pstricks-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetex-tibetan-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetexconfig-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xetexfontinfo-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xifthen-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xkeyval-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xltxtra-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xmltex-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xmltexconfig-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xpatch-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xstring-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xtab-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-xunicode-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-zapfchan-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-zapfding-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'},
    {'reference':'texlive-zref-20200406-26.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'9'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'texlive / texlive-acronym / texlive-adjustbox / texlive-ae / etc');
}
