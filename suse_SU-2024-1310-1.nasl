#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1310-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(193391);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/20");

  script_cve_id("CVE-2023-46048", "CVE-2023-46051");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1310-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : texlive (SUSE-SU-2024:1310-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:1310-1 advisory.

  - Tex Live 944e257 has a NULL pointer dereference in texk/web2c/pdftexdir/writet1.c. NOTE: this is disputed
    because it should be categorized as a usability problem. (CVE-2023-46048)

  - TeX Live 944e257 allows a NULL pointer dereference in texk/web2c/pdftexdir/tounicode.c. NOTE: this is
    disputed because it should be categorized as a usability problem. (CVE-2023-46051)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222126");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222127");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-April/034988.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46048");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46051");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-46051");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-46048");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libkpathsea6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libptexenc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsynctex2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtexlua53-5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtexluajit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-biber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-a2ping-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-accfonts-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-adhocfilelist-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-afm2pl-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-albatross-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-aleph-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-amstex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-arara-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-asymptote-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-attachfile2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-authorindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-autosp-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-axodraw2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bib2gls-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-biber-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibexport-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibtex8-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bibtexu-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-bundledoc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cachepic-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-checkcites-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-checklistings-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-chklref-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-chktex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cjk-gs-integrate-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cjkutils-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-clojure-pamphlet-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cluttex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-context-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-convbkmk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-crossrefware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cslatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-csplain-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctan-o-mat-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctanbib-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctanify-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctanupload-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ctie-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cweb-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-cyrillic-bin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-de-macro-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-detex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-diadia-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dosepsbin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dtl-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dtxgen-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviasm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvicopy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvidvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviinfox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviljk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dviout-util-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipdfmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipng-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvipos-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvips-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-dvisvgm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-eplain-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-epspdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-epstopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-exceltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fig4latex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-findhyph-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fontinst-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fontools-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fontware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-fragmaster-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-getmap-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-git-latexdiff-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-glossaries-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-gregoriotex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-gsftopk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-hyperxmp-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-jadetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-jfmutil-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ketcindy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kotex-utils-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kpathsea-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-kpathsea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-l3build-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lacheck-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-bin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-bin-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-git-log-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex-papersize-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex2man-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latex2nemeth-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexdiff-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexfileversion-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexindent-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexmk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-latexpand-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lcdftypetools-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-light-latex-make-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lilyglyphs-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-listbib-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-listings-ext-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lollipop-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ltxfileinfo-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ltximg-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luahbtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luajittex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luaotfload-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-luatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-lwarp-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-m-tx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-make4ht-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-makedtx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-makeindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-match_parens-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mathspic-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-metafont-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-metapost-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mf2pt1-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mflua-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mfware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mkgrkindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mkjobtexmf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mkpic-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-mptopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-multibibliography-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-musixtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-musixtnt-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-omegaware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-optex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-patgen-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pax-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfbook2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfcrop-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfjam-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdflatexpicscale-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdftex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdftex-quiet-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdftosrc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pdfxup-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pedigree-perl-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-perltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-petri-nets-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pfarrei-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pkfix-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pkfix-helper-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-platex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pmxchords-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ps2eps-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ps2pk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pst-pdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pst2pdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptex-fontmaps-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptex2pdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ptexenc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-purifyeps-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pygmentex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-pythontex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-rubik-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-scripts-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-scripts-extra-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-seetexk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-spix-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-splitindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-srcredact-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-sty2dtx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-svn-multi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-synctex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-synctex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex4ebook-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tex4ht-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texcount-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdef-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdiff-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdirflatten-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdoc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texdoctk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texfot-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texliveonfly-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texloganalyser-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texlua-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texluajit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texosquery-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texplate-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texsis-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-texware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-thumbpdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tie-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tikztosvg-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-tpic2pdftex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ttfutils-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-typeoutfileinfo-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-ulqda-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-uplatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-uptex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-urlbst-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-velthuis-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-vlna-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-vpe-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-web-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-webquiz-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-wordcount-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xdvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xelatex-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xml2pmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xmltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-xpdfopen-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:texlive-yplan-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libkpathsea6-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libkpathsea6-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libptexenc1-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libptexenc1-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libsynctex2-1.21-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libsynctex2-1.21-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libtexlua53-5-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libtexlua53-5-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'perl-biber-2021.20210325.svn30357-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'perl-biber-2021.20210325.svn30357-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-a2ping-bin-2021.20210325.svn27321-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-a2ping-bin-2021.20210325.svn27321-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-accfonts-bin-2021.20210325.svn12688-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-accfonts-bin-2021.20210325.svn12688-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-adhocfilelist-bin-2021.20210325.svn28038-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-adhocfilelist-bin-2021.20210325.svn28038-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-afm2pl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-afm2pl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-albatross-bin-2021.20210325.svn57089-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-albatross-bin-2021.20210325.svn57089-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-aleph-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-aleph-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-amstex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-amstex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-arara-bin-2021.20210325.svn29036-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-arara-bin-2021.20210325.svn29036-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-asymptote-bin-2021.20210325.svn57890-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-asymptote-bin-2021.20210325.svn57890-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-attachfile2-bin-2021.20210325.svn52909-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-attachfile2-bin-2021.20210325.svn52909-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-authorindex-bin-2021.20210325.svn18790-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-authorindex-bin-2021.20210325.svn18790-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-autosp-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-autosp-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-axodraw2-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-axodraw2-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bib2gls-bin-2021.20210325.svn45266-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bib2gls-bin-2021.20210325.svn45266-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-biber-bin-2021.20210325.svn57273-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-biber-bin-2021.20210325.svn57273-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibexport-bin-2021.20210325.svn16219-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibexport-bin-2021.20210325.svn16219-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibtex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibtex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibtex8-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibtex8-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibtexu-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bibtexu-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bin-devel-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bin-devel-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bundledoc-bin-2021.20210325.svn17794-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-bundledoc-bin-2021.20210325.svn17794-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cachepic-bin-2021.20210325.svn15543-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cachepic-bin-2021.20210325.svn15543-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-checkcites-bin-2021.20210325.svn25623-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-checkcites-bin-2021.20210325.svn25623-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-checklistings-bin-2021.20210325.svn38300-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-checklistings-bin-2021.20210325.svn38300-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-chklref-bin-2021.20210325.svn52631-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-chklref-bin-2021.20210325.svn52631-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-chktex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-chktex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cjk-gs-integrate-bin-2021.20210325.svn37223-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cjk-gs-integrate-bin-2021.20210325.svn37223-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cjkutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cjkutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-clojure-pamphlet-bin-2021.20210325.svn51944-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-clojure-pamphlet-bin-2021.20210325.svn51944-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cluttex-bin-2021.20210325.svn48871-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cluttex-bin-2021.20210325.svn48871-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-context-bin-2021.20210325.svn34112-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-context-bin-2021.20210325.svn34112-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-convbkmk-bin-2021.20210325.svn30408-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-convbkmk-bin-2021.20210325.svn30408-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-crossrefware-bin-2021.20210325.svn45927-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-crossrefware-bin-2021.20210325.svn45927-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cslatex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cslatex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-csplain-bin-2021.20210325.svn50528-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-csplain-bin-2021.20210325.svn50528-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctan-o-mat-bin-2021.20210325.svn46996-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctan-o-mat-bin-2021.20210325.svn46996-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctanbib-bin-2021.20210325.svn48478-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctanbib-bin-2021.20210325.svn48478-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctanify-bin-2021.20210325.svn24061-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctanify-bin-2021.20210325.svn24061-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctanupload-bin-2021.20210325.svn23866-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctanupload-bin-2021.20210325.svn23866-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ctie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cweb-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cweb-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cyrillic-bin-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-cyrillic-bin-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-de-macro-bin-2021.20210325.svn17399-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-de-macro-bin-2021.20210325.svn17399-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-detex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-detex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-diadia-bin-2021.20210325.svn37645-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-diadia-bin-2021.20210325.svn37645-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dosepsbin-bin-2021.20210325.svn24759-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dosepsbin-bin-2021.20210325.svn24759-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dtl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dtl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dtxgen-bin-2021.20210325.svn29031-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dtxgen-bin-2021.20210325.svn29031-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviasm-bin-2021.20210325.svn8329-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviasm-bin-2021.20210325.svn8329-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvicopy-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvicopy-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvidvi-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvidvi-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviinfox-bin-2021.20210325.svn44515-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviinfox-bin-2021.20210325.svn44515-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviljk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviljk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviout-util-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dviout-util-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvipdfmx-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvipdfmx-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvipng-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvipng-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvipos-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvipos-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvips-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvips-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvisvgm-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-dvisvgm-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-eplain-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-eplain-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-epspdf-bin-2021.20210325.svn29050-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-epspdf-bin-2021.20210325.svn29050-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-epstopdf-bin-2021.20210325.svn18336-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-epstopdf-bin-2021.20210325.svn18336-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-exceltex-bin-2021.20210325.svn25860-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-exceltex-bin-2021.20210325.svn25860-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fig4latex-bin-2021.20210325.svn14752-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fig4latex-bin-2021.20210325.svn14752-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-findhyph-bin-2021.20210325.svn14758-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-findhyph-bin-2021.20210325.svn14758-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fontinst-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fontinst-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fontools-bin-2021.20210325.svn25997-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fontools-bin-2021.20210325.svn25997-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fontware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fontware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fragmaster-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-fragmaster-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-getmap-bin-2021.20210325.svn34971-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-getmap-bin-2021.20210325.svn34971-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-git-latexdiff-bin-2021.20210325.svn54732-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-git-latexdiff-bin-2021.20210325.svn54732-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-glossaries-bin-2021.20210325.svn37813-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-glossaries-bin-2021.20210325.svn37813-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-gregoriotex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-gregoriotex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-gsftopk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-gsftopk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-hyperxmp-bin-2021.20210325.svn56984-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-hyperxmp-bin-2021.20210325.svn56984-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-jadetex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-jadetex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-jfmutil-bin-2021.20210325.svn44835-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-jfmutil-bin-2021.20210325.svn44835-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ketcindy-bin-2021.20210325.svn49033-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ketcindy-bin-2021.20210325.svn49033-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-kotex-utils-bin-2021.20210325.svn32101-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-kotex-utils-bin-2021.20210325.svn32101-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-kpathsea-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-kpathsea-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-kpathsea-devel-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-kpathsea-devel-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-l3build-bin-2021.20210325.svn46894-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-l3build-bin-2021.20210325.svn46894-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lacheck-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lacheck-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-bin-bin-2021.20210325.svn54358-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-bin-bin-2021.20210325.svn54358-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-bin-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-bin-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-git-log-bin-2021.20210325.svn30983-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-git-log-bin-2021.20210325.svn30983-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-papersize-bin-2021.20210325.svn42296-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex-papersize-bin-2021.20210325.svn42296-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex2man-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex2man-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex2nemeth-bin-2021.20210325.svn42300-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latex2nemeth-bin-2021.20210325.svn42300-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexdiff-bin-2021.20210325.svn16420-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexdiff-bin-2021.20210325.svn16420-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexfileversion-bin-2021.20210325.svn25012-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexfileversion-bin-2021.20210325.svn25012-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexindent-bin-2021.20210325.svn32150-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexindent-bin-2021.20210325.svn32150-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexmk-bin-2021.20210325.svn10937-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexmk-bin-2021.20210325.svn10937-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexpand-bin-2021.20210325.svn27025-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-latexpand-bin-2021.20210325.svn27025-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lcdftypetools-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lcdftypetools-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-light-latex-make-bin-2021.20210325.svn56352-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-light-latex-make-bin-2021.20210325.svn56352-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lilyglyphs-bin-2021.20210325.svn31696-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lilyglyphs-bin-2021.20210325.svn31696-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-listbib-bin-2021.20210325.svn26126-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-listbib-bin-2021.20210325.svn26126-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-listings-ext-bin-2021.20210325.svn15093-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-listings-ext-bin-2021.20210325.svn15093-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lollipop-bin-2021.20210325.svn41465-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lollipop-bin-2021.20210325.svn41465-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ltxfileinfo-bin-2021.20210325.svn29005-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ltxfileinfo-bin-2021.20210325.svn29005-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ltximg-bin-2021.20210325.svn32346-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ltximg-bin-2021.20210325.svn32346-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luahbtex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luahbtex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luajittex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luajittex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luaotfload-bin-2021.20210325.svn34647-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luaotfload-bin-2021.20210325.svn34647-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luatex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-luatex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lwarp-bin-2021.20210325.svn43292-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-lwarp-bin-2021.20210325.svn43292-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-m-tx-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-m-tx-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-make4ht-bin-2021.20210325.svn37750-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-make4ht-bin-2021.20210325.svn37750-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-makedtx-bin-2021.20210325.svn38769-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-makedtx-bin-2021.20210325.svn38769-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-makeindex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-makeindex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-match_parens-bin-2021.20210325.svn23500-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-match_parens-bin-2021.20210325.svn23500-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mathspic-bin-2021.20210325.svn23661-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mathspic-bin-2021.20210325.svn23661-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-metafont-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-metafont-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-metapost-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-metapost-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mf2pt1-bin-2021.20210325.svn23406-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mf2pt1-bin-2021.20210325.svn23406-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mflua-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mflua-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mfware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mfware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mkgrkindex-bin-2021.20210325.svn14428-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mkgrkindex-bin-2021.20210325.svn14428-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mkjobtexmf-bin-2021.20210325.svn8457-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mkjobtexmf-bin-2021.20210325.svn8457-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mkpic-bin-2021.20210325.svn33688-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mkpic-bin-2021.20210325.svn33688-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mptopdf-bin-2021.20210325.svn18674-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-mptopdf-bin-2021.20210325.svn18674-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-multibibliography-bin-2021.20210325.svn30534-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-multibibliography-bin-2021.20210325.svn30534-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-musixtex-bin-2021.20210325.svn37026-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-musixtex-bin-2021.20210325.svn37026-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-musixtnt-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-musixtnt-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-omegaware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-omegaware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-optex-bin-2021.20210325.svn53804-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-optex-bin-2021.20210325.svn53804-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-patgen-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-patgen-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pax-bin-2021.20210325.svn10843-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pax-bin-2021.20210325.svn10843-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfbook2-bin-2021.20210325.svn37537-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfbook2-bin-2021.20210325.svn37537-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfcrop-bin-2021.20210325.svn14387-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfcrop-bin-2021.20210325.svn14387-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfjam-bin-2021.20210325.svn52858-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfjam-bin-2021.20210325.svn52858-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdflatexpicscale-bin-2021.20210325.svn41779-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdflatexpicscale-bin-2021.20210325.svn41779-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdftex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdftex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdftex-quiet-bin-2021.20210325.svn49140-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdftex-quiet-bin-2021.20210325.svn49140-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdftosrc-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdftosrc-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfxup-bin-2021.20210325.svn40690-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pdfxup-bin-2021.20210325.svn40690-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pedigree-perl-bin-2021.20210325.svn25962-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pedigree-perl-bin-2021.20210325.svn25962-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-perltex-bin-2021.20210325.svn16181-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-perltex-bin-2021.20210325.svn16181-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-petri-nets-bin-2021.20210325.svn39165-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-petri-nets-bin-2021.20210325.svn39165-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pfarrei-bin-2021.20210325.svn29348-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pfarrei-bin-2021.20210325.svn29348-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pkfix-bin-2021.20210325.svn13364-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pkfix-bin-2021.20210325.svn13364-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pkfix-helper-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pkfix-helper-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-platex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-platex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pmxchords-bin-2021.20210325.svn32405-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pmxchords-bin-2021.20210325.svn32405-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ps2eps-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ps2eps-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ps2pk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ps2pk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pst-pdf-bin-2021.20210325.svn7838-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pst-pdf-bin-2021.20210325.svn7838-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pst2pdf-bin-2021.20210325.svn29333-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pst2pdf-bin-2021.20210325.svn29333-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptex-fontmaps-bin-2021.20210325.svn44206-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptex-fontmaps-bin-2021.20210325.svn44206-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptex2pdf-bin-2021.20210325.svn29335-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptex2pdf-bin-2021.20210325.svn29335-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptexenc-devel-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ptexenc-devel-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-purifyeps-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-purifyeps-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pygmentex-bin-2021.20210325.svn34996-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pygmentex-bin-2021.20210325.svn34996-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pythontex-bin-2021.20210325.svn31638-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-pythontex-bin-2021.20210325.svn31638-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-rubik-bin-2021.20210325.svn32919-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-rubik-bin-2021.20210325.svn32919-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-scripts-bin-2021.20210325.svn55172-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-scripts-bin-2021.20210325.svn55172-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-scripts-extra-bin-2021.20210325.svn53577-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-scripts-extra-bin-2021.20210325.svn53577-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-seetexk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-seetexk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-spix-bin-2021.20210325.svn55933-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-spix-bin-2021.20210325.svn55933-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-splitindex-bin-2021.20210325.svn29688-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-splitindex-bin-2021.20210325.svn29688-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-srcredact-bin-2021.20210325.svn38710-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-srcredact-bin-2021.20210325.svn38710-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-sty2dtx-bin-2021.20210325.svn21215-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-sty2dtx-bin-2021.20210325.svn21215-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-svn-multi-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-svn-multi-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-synctex-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-synctex-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-synctex-devel-1.21-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-synctex-devel-1.21-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tex4ebook-bin-2021.20210325.svn37771-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tex4ebook-bin-2021.20210325.svn37771-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tex4ht-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tex4ht-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texcount-bin-2021.20210325.svn13013-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texcount-bin-2021.20210325.svn13013-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdef-bin-2021.20210325.svn45011-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdef-bin-2021.20210325.svn45011-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdiff-bin-2021.20210325.svn15506-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdiff-bin-2021.20210325.svn15506-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdirflatten-bin-2021.20210325.svn12782-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdirflatten-bin-2021.20210325.svn12782-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdoc-bin-2021.20210325.svn47948-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdoc-bin-2021.20210325.svn47948-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdoctk-bin-2021.20210325.svn29741-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texdoctk-bin-2021.20210325.svn29741-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texfot-bin-2021.20210325.svn33155-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texfot-bin-2021.20210325.svn33155-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texliveonfly-bin-2021.20210325.svn24062-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texliveonfly-bin-2021.20210325.svn24062-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texloganalyser-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texloganalyser-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texlua-devel-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texlua-devel-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texosquery-bin-2021.20210325.svn43596-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texosquery-bin-2021.20210325.svn43596-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texplate-bin-2021.20210325.svn53444-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texplate-bin-2021.20210325.svn53444-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texsis-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texsis-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-texware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-thumbpdf-bin-2021.20210325.svn6898-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-thumbpdf-bin-2021.20210325.svn6898-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tikztosvg-bin-2021.20210325.svn55132-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tikztosvg-bin-2021.20210325.svn55132-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tpic2pdftex-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-tpic2pdftex-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ttfutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ttfutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-typeoutfileinfo-bin-2021.20210325.svn25648-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-typeoutfileinfo-bin-2021.20210325.svn25648-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ulqda-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-ulqda-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-uplatex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-uplatex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-uptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-uptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-urlbst-bin-2021.20210325.svn23262-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-urlbst-bin-2021.20210325.svn23262-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-velthuis-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-velthuis-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-vlna-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-vlna-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-vpe-bin-2021.20210325.svn6897-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-vpe-bin-2021.20210325.svn6897-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-web-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-web-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-webquiz-bin-2021.20210325.svn50419-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-webquiz-bin-2021.20210325.svn50419-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-wordcount-bin-2021.20210325.svn46165-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-wordcount-bin-2021.20210325.svn46165-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xdvi-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xdvi-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xelatex-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xelatex-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xetex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xetex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xindex-bin-2021.20210325.svn49312-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xindex-bin-2021.20210325.svn49312-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xml2pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xml2pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xmltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xmltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xpdfopen-bin-2021.20210325.svn52917-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-xpdfopen-bin-2021.20210325.svn52917-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-yplan-bin-2021.20210325.svn34398-150400.31.6.4', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'texlive-yplan-bin-2021.20210325.svn34398-150400.31.6.4', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libkpathsea6-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libkpathsea6-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libptexenc1-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libptexenc1-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libsynctex2-1.21-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libsynctex2-1.21-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libtexlua53-5-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libtexlua53-5-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'perl-biber-2021.20210325.svn30357-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'perl-biber-2021.20210325.svn30357-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-a2ping-bin-2021.20210325.svn27321-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-a2ping-bin-2021.20210325.svn27321-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-accfonts-bin-2021.20210325.svn12688-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-accfonts-bin-2021.20210325.svn12688-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-adhocfilelist-bin-2021.20210325.svn28038-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-adhocfilelist-bin-2021.20210325.svn28038-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-afm2pl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-afm2pl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-albatross-bin-2021.20210325.svn57089-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-albatross-bin-2021.20210325.svn57089-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-aleph-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-aleph-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-amstex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-amstex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-arara-bin-2021.20210325.svn29036-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-arara-bin-2021.20210325.svn29036-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-asymptote-bin-2021.20210325.svn57890-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-asymptote-bin-2021.20210325.svn57890-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-attachfile2-bin-2021.20210325.svn52909-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-attachfile2-bin-2021.20210325.svn52909-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-authorindex-bin-2021.20210325.svn18790-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-authorindex-bin-2021.20210325.svn18790-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-autosp-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-autosp-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-axodraw2-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-axodraw2-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bib2gls-bin-2021.20210325.svn45266-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bib2gls-bin-2021.20210325.svn45266-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-biber-bin-2021.20210325.svn57273-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-biber-bin-2021.20210325.svn57273-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibexport-bin-2021.20210325.svn16219-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibexport-bin-2021.20210325.svn16219-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibtex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibtex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibtex8-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibtex8-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibtexu-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bibtexu-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bin-devel-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bin-devel-2021.20210325-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bundledoc-bin-2021.20210325.svn17794-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-bundledoc-bin-2021.20210325.svn17794-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cachepic-bin-2021.20210325.svn15543-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cachepic-bin-2021.20210325.svn15543-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-checkcites-bin-2021.20210325.svn25623-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-checkcites-bin-2021.20210325.svn25623-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-checklistings-bin-2021.20210325.svn38300-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-checklistings-bin-2021.20210325.svn38300-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-chklref-bin-2021.20210325.svn52631-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-chklref-bin-2021.20210325.svn52631-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-chktex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-chktex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cjk-gs-integrate-bin-2021.20210325.svn37223-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cjk-gs-integrate-bin-2021.20210325.svn37223-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cjkutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cjkutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-clojure-pamphlet-bin-2021.20210325.svn51944-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-clojure-pamphlet-bin-2021.20210325.svn51944-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cluttex-bin-2021.20210325.svn48871-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cluttex-bin-2021.20210325.svn48871-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-context-bin-2021.20210325.svn34112-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-context-bin-2021.20210325.svn34112-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-convbkmk-bin-2021.20210325.svn30408-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-convbkmk-bin-2021.20210325.svn30408-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-crossrefware-bin-2021.20210325.svn45927-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-crossrefware-bin-2021.20210325.svn45927-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cslatex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cslatex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-csplain-bin-2021.20210325.svn50528-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-csplain-bin-2021.20210325.svn50528-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctan-o-mat-bin-2021.20210325.svn46996-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctan-o-mat-bin-2021.20210325.svn46996-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctanbib-bin-2021.20210325.svn48478-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctanbib-bin-2021.20210325.svn48478-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctanify-bin-2021.20210325.svn24061-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctanify-bin-2021.20210325.svn24061-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctanupload-bin-2021.20210325.svn23866-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctanupload-bin-2021.20210325.svn23866-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ctie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cweb-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cweb-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cyrillic-bin-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-cyrillic-bin-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-de-macro-bin-2021.20210325.svn17399-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-de-macro-bin-2021.20210325.svn17399-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-detex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-detex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-diadia-bin-2021.20210325.svn37645-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-diadia-bin-2021.20210325.svn37645-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dosepsbin-bin-2021.20210325.svn24759-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dosepsbin-bin-2021.20210325.svn24759-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dtl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dtl-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dtxgen-bin-2021.20210325.svn29031-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dtxgen-bin-2021.20210325.svn29031-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviasm-bin-2021.20210325.svn8329-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviasm-bin-2021.20210325.svn8329-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvicopy-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvicopy-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvidvi-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvidvi-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviinfox-bin-2021.20210325.svn44515-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviinfox-bin-2021.20210325.svn44515-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviljk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviljk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviout-util-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dviout-util-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvipdfmx-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvipdfmx-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvipng-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvipng-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvipos-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvipos-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvips-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvips-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvisvgm-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-dvisvgm-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-eplain-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-eplain-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-epspdf-bin-2021.20210325.svn29050-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-epspdf-bin-2021.20210325.svn29050-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-epstopdf-bin-2021.20210325.svn18336-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-epstopdf-bin-2021.20210325.svn18336-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-exceltex-bin-2021.20210325.svn25860-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-exceltex-bin-2021.20210325.svn25860-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fig4latex-bin-2021.20210325.svn14752-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fig4latex-bin-2021.20210325.svn14752-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-findhyph-bin-2021.20210325.svn14758-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-findhyph-bin-2021.20210325.svn14758-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fontinst-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fontinst-bin-2021.20210325.svn53554-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fontools-bin-2021.20210325.svn25997-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fontools-bin-2021.20210325.svn25997-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fontware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fontware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fragmaster-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-fragmaster-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-getmap-bin-2021.20210325.svn34971-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-getmap-bin-2021.20210325.svn34971-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-git-latexdiff-bin-2021.20210325.svn54732-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-git-latexdiff-bin-2021.20210325.svn54732-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-glossaries-bin-2021.20210325.svn37813-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-glossaries-bin-2021.20210325.svn37813-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-gregoriotex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-gregoriotex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-gsftopk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-gsftopk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-hyperxmp-bin-2021.20210325.svn56984-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-hyperxmp-bin-2021.20210325.svn56984-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-jadetex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-jadetex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-jfmutil-bin-2021.20210325.svn44835-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-jfmutil-bin-2021.20210325.svn44835-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ketcindy-bin-2021.20210325.svn49033-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ketcindy-bin-2021.20210325.svn49033-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-kotex-utils-bin-2021.20210325.svn32101-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-kotex-utils-bin-2021.20210325.svn32101-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-kpathsea-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-kpathsea-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-kpathsea-devel-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-kpathsea-devel-6.3.3-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-l3build-bin-2021.20210325.svn46894-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-l3build-bin-2021.20210325.svn46894-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lacheck-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lacheck-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-bin-bin-2021.20210325.svn54358-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-bin-bin-2021.20210325.svn54358-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-bin-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-bin-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-git-log-bin-2021.20210325.svn30983-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-git-log-bin-2021.20210325.svn30983-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-papersize-bin-2021.20210325.svn42296-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex-papersize-bin-2021.20210325.svn42296-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex2man-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex2man-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex2nemeth-bin-2021.20210325.svn42300-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latex2nemeth-bin-2021.20210325.svn42300-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexdiff-bin-2021.20210325.svn16420-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexdiff-bin-2021.20210325.svn16420-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexfileversion-bin-2021.20210325.svn25012-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexfileversion-bin-2021.20210325.svn25012-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexindent-bin-2021.20210325.svn32150-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexindent-bin-2021.20210325.svn32150-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexmk-bin-2021.20210325.svn10937-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexmk-bin-2021.20210325.svn10937-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexpand-bin-2021.20210325.svn27025-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-latexpand-bin-2021.20210325.svn27025-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lcdftypetools-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lcdftypetools-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-light-latex-make-bin-2021.20210325.svn56352-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-light-latex-make-bin-2021.20210325.svn56352-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lilyglyphs-bin-2021.20210325.svn31696-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lilyglyphs-bin-2021.20210325.svn31696-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-listbib-bin-2021.20210325.svn26126-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-listbib-bin-2021.20210325.svn26126-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-listings-ext-bin-2021.20210325.svn15093-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-listings-ext-bin-2021.20210325.svn15093-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lollipop-bin-2021.20210325.svn41465-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lollipop-bin-2021.20210325.svn41465-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ltxfileinfo-bin-2021.20210325.svn29005-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ltxfileinfo-bin-2021.20210325.svn29005-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ltximg-bin-2021.20210325.svn32346-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ltximg-bin-2021.20210325.svn32346-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luahbtex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luahbtex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luajittex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luajittex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luaotfload-bin-2021.20210325.svn34647-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luaotfload-bin-2021.20210325.svn34647-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luatex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-luatex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lwarp-bin-2021.20210325.svn43292-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-lwarp-bin-2021.20210325.svn43292-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-m-tx-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-m-tx-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-make4ht-bin-2021.20210325.svn37750-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-make4ht-bin-2021.20210325.svn37750-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-makedtx-bin-2021.20210325.svn38769-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-makedtx-bin-2021.20210325.svn38769-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-makeindex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-makeindex-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-match_parens-bin-2021.20210325.svn23500-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-match_parens-bin-2021.20210325.svn23500-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mathspic-bin-2021.20210325.svn23661-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mathspic-bin-2021.20210325.svn23661-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-metafont-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-metafont-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-metapost-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-metapost-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mf2pt1-bin-2021.20210325.svn23406-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mf2pt1-bin-2021.20210325.svn23406-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mflua-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mflua-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mfware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mfware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mkgrkindex-bin-2021.20210325.svn14428-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mkgrkindex-bin-2021.20210325.svn14428-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mkjobtexmf-bin-2021.20210325.svn8457-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mkjobtexmf-bin-2021.20210325.svn8457-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mkpic-bin-2021.20210325.svn33688-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mkpic-bin-2021.20210325.svn33688-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mptopdf-bin-2021.20210325.svn18674-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-mptopdf-bin-2021.20210325.svn18674-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-multibibliography-bin-2021.20210325.svn30534-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-multibibliography-bin-2021.20210325.svn30534-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-musixtex-bin-2021.20210325.svn37026-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-musixtex-bin-2021.20210325.svn37026-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-musixtnt-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-musixtnt-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-omegaware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-omegaware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-optex-bin-2021.20210325.svn53804-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-optex-bin-2021.20210325.svn53804-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-patgen-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-patgen-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pax-bin-2021.20210325.svn10843-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pax-bin-2021.20210325.svn10843-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfbook2-bin-2021.20210325.svn37537-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfbook2-bin-2021.20210325.svn37537-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfcrop-bin-2021.20210325.svn14387-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfcrop-bin-2021.20210325.svn14387-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfjam-bin-2021.20210325.svn52858-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfjam-bin-2021.20210325.svn52858-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdflatexpicscale-bin-2021.20210325.svn41779-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdflatexpicscale-bin-2021.20210325.svn41779-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdftex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdftex-bin-2021.20210325.svn58535-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdftex-quiet-bin-2021.20210325.svn49140-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdftex-quiet-bin-2021.20210325.svn49140-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdftosrc-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdftosrc-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfxup-bin-2021.20210325.svn40690-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pdfxup-bin-2021.20210325.svn40690-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pedigree-perl-bin-2021.20210325.svn25962-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pedigree-perl-bin-2021.20210325.svn25962-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-perltex-bin-2021.20210325.svn16181-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-perltex-bin-2021.20210325.svn16181-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-petri-nets-bin-2021.20210325.svn39165-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-petri-nets-bin-2021.20210325.svn39165-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pfarrei-bin-2021.20210325.svn29348-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pfarrei-bin-2021.20210325.svn29348-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pkfix-bin-2021.20210325.svn13364-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pkfix-bin-2021.20210325.svn13364-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pkfix-helper-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pkfix-helper-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-platex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-platex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pmxchords-bin-2021.20210325.svn32405-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pmxchords-bin-2021.20210325.svn32405-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ps2eps-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ps2eps-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ps2pk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ps2pk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pst-pdf-bin-2021.20210325.svn7838-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pst-pdf-bin-2021.20210325.svn7838-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pst2pdf-bin-2021.20210325.svn29333-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pst2pdf-bin-2021.20210325.svn29333-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptex-fontmaps-bin-2021.20210325.svn44206-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptex-fontmaps-bin-2021.20210325.svn44206-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptex2pdf-bin-2021.20210325.svn29335-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptex2pdf-bin-2021.20210325.svn29335-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptexenc-devel-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ptexenc-devel-1.3.9-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-purifyeps-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-purifyeps-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pygmentex-bin-2021.20210325.svn34996-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pygmentex-bin-2021.20210325.svn34996-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pythontex-bin-2021.20210325.svn31638-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-pythontex-bin-2021.20210325.svn31638-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-rubik-bin-2021.20210325.svn32919-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-rubik-bin-2021.20210325.svn32919-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-scripts-bin-2021.20210325.svn55172-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-scripts-bin-2021.20210325.svn55172-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-scripts-extra-bin-2021.20210325.svn53577-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-scripts-extra-bin-2021.20210325.svn53577-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-seetexk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-seetexk-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-spix-bin-2021.20210325.svn55933-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-spix-bin-2021.20210325.svn55933-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-splitindex-bin-2021.20210325.svn29688-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-splitindex-bin-2021.20210325.svn29688-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-srcredact-bin-2021.20210325.svn38710-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-srcredact-bin-2021.20210325.svn38710-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-sty2dtx-bin-2021.20210325.svn21215-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-sty2dtx-bin-2021.20210325.svn21215-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-svn-multi-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-svn-multi-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-synctex-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-synctex-bin-2021.20210325.svn58136-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-synctex-devel-1.21-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-synctex-devel-1.21-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tex4ebook-bin-2021.20210325.svn37771-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tex4ebook-bin-2021.20210325.svn37771-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tex4ht-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tex4ht-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texcount-bin-2021.20210325.svn13013-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texcount-bin-2021.20210325.svn13013-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdef-bin-2021.20210325.svn45011-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdef-bin-2021.20210325.svn45011-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdiff-bin-2021.20210325.svn15506-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdiff-bin-2021.20210325.svn15506-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdirflatten-bin-2021.20210325.svn12782-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdirflatten-bin-2021.20210325.svn12782-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdoc-bin-2021.20210325.svn47948-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdoc-bin-2021.20210325.svn47948-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdoctk-bin-2021.20210325.svn29741-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texdoctk-bin-2021.20210325.svn29741-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texfot-bin-2021.20210325.svn33155-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texfot-bin-2021.20210325.svn33155-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texliveonfly-bin-2021.20210325.svn24062-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texliveonfly-bin-2021.20210325.svn24062-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texloganalyser-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texloganalyser-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texlua-devel-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texlua-devel-5.3.6-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texosquery-bin-2021.20210325.svn43596-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texosquery-bin-2021.20210325.svn43596-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texplate-bin-2021.20210325.svn53444-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texplate-bin-2021.20210325.svn53444-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texsis-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texsis-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-texware-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-thumbpdf-bin-2021.20210325.svn6898-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-thumbpdf-bin-2021.20210325.svn6898-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tie-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tikztosvg-bin-2021.20210325.svn55132-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tikztosvg-bin-2021.20210325.svn55132-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tpic2pdftex-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-tpic2pdftex-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ttfutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ttfutils-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-typeoutfileinfo-bin-2021.20210325.svn25648-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-typeoutfileinfo-bin-2021.20210325.svn25648-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ulqda-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-ulqda-bin-2021.20210325.svn13663-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-uplatex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-uplatex-bin-2021.20210325.svn52800-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-uptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-uptex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-urlbst-bin-2021.20210325.svn23262-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-urlbst-bin-2021.20210325.svn23262-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-velthuis-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-velthuis-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-vlna-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-vlna-bin-2021.20210325.svn50281-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-vpe-bin-2021.20210325.svn6897-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-vpe-bin-2021.20210325.svn6897-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-web-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-web-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-webquiz-bin-2021.20210325.svn50419-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-webquiz-bin-2021.20210325.svn50419-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-wordcount-bin-2021.20210325.svn46165-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-wordcount-bin-2021.20210325.svn46165-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xdvi-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xdvi-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xelatex-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xelatex-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xetex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xetex-bin-2021.20210325.svn58378-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xindex-bin-2021.20210325.svn49312-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xindex-bin-2021.20210325.svn49312-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xml2pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xml2pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xmltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xmltex-bin-2021.20210325.svn3006-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xpdfopen-bin-2021.20210325.svn52917-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-xpdfopen-bin-2021.20210325.svn52917-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-yplan-bin-2021.20210325.svn34398-150400.31.6.4', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'texlive-yplan-bin-2021.20210325.svn34398-150400.31.6.4', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-desktop-applications-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libkpathsea6-6.3.3-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libptexenc1-1.3.9-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libsynctex2-1.21-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libtexlua53-5-5.3.6-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libtexluajit2-2.1.0beta3-150400.31.6.4', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'perl-biber-2021.20210325.svn30357-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-2021.20210325-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-a2ping-bin-2021.20210325.svn27321-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-accfonts-bin-2021.20210325.svn12688-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-adhocfilelist-bin-2021.20210325.svn28038-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-afm2pl-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-albatross-bin-2021.20210325.svn57089-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-aleph-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-amstex-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-arara-bin-2021.20210325.svn29036-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-asymptote-bin-2021.20210325.svn57890-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-attachfile2-bin-2021.20210325.svn52909-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-authorindex-bin-2021.20210325.svn18790-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-autosp-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-axodraw2-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-bib2gls-bin-2021.20210325.svn45266-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-biber-bin-2021.20210325.svn57273-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-bibexport-bin-2021.20210325.svn16219-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-bibtex-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-bibtex8-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-bibtexu-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-bin-devel-2021.20210325-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-bundledoc-bin-2021.20210325.svn17794-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-cachepic-bin-2021.20210325.svn15543-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-checkcites-bin-2021.20210325.svn25623-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-checklistings-bin-2021.20210325.svn38300-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-chklref-bin-2021.20210325.svn52631-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-chktex-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-cjk-gs-integrate-bin-2021.20210325.svn37223-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-cjkutils-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-clojure-pamphlet-bin-2021.20210325.svn51944-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-cluttex-bin-2021.20210325.svn48871-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-context-bin-2021.20210325.svn34112-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-convbkmk-bin-2021.20210325.svn30408-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-crossrefware-bin-2021.20210325.svn45927-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-cslatex-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-csplain-bin-2021.20210325.svn50528-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ctan-o-mat-bin-2021.20210325.svn46996-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ctanbib-bin-2021.20210325.svn48478-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ctanify-bin-2021.20210325.svn24061-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ctanupload-bin-2021.20210325.svn23866-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ctie-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-cweb-bin-2021.20210325.svn58136-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-cyrillic-bin-bin-2021.20210325.svn53554-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-de-macro-bin-2021.20210325.svn17399-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-detex-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-diadia-bin-2021.20210325.svn37645-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dosepsbin-bin-2021.20210325.svn24759-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dtl-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dtxgen-bin-2021.20210325.svn29031-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dviasm-bin-2021.20210325.svn8329-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dvicopy-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dvidvi-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dviinfox-bin-2021.20210325.svn44515-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dviljk-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dviout-util-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dvipdfmx-bin-2021.20210325.svn58535-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dvipng-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dvipos-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dvips-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-dvisvgm-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-eplain-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-epspdf-bin-2021.20210325.svn29050-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-epstopdf-bin-2021.20210325.svn18336-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-exceltex-bin-2021.20210325.svn25860-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-fig4latex-bin-2021.20210325.svn14752-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-findhyph-bin-2021.20210325.svn14758-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-fontinst-bin-2021.20210325.svn53554-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-fontools-bin-2021.20210325.svn25997-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-fontware-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-fragmaster-bin-2021.20210325.svn13663-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-getmap-bin-2021.20210325.svn34971-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-git-latexdiff-bin-2021.20210325.svn54732-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-glossaries-bin-2021.20210325.svn37813-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-gregoriotex-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-gsftopk-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-hyperxmp-bin-2021.20210325.svn56984-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-jadetex-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-jfmutil-bin-2021.20210325.svn44835-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ketcindy-bin-2021.20210325.svn49033-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-kotex-utils-bin-2021.20210325.svn32101-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-kpathsea-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-kpathsea-devel-6.3.3-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-l3build-bin-2021.20210325.svn46894-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-lacheck-bin-2021.20210325.svn53999-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latex-bin-bin-2021.20210325.svn54358-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latex-bin-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latex-git-log-bin-2021.20210325.svn30983-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latex-papersize-bin-2021.20210325.svn42296-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latex2man-bin-2021.20210325.svn13663-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latex2nemeth-bin-2021.20210325.svn42300-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latexdiff-bin-2021.20210325.svn16420-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latexfileversion-bin-2021.20210325.svn25012-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latexindent-bin-2021.20210325.svn32150-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latexmk-bin-2021.20210325.svn10937-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-latexpand-bin-2021.20210325.svn27025-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-lcdftypetools-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-light-latex-make-bin-2021.20210325.svn56352-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-lilyglyphs-bin-2021.20210325.svn31696-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-listbib-bin-2021.20210325.svn26126-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-listings-ext-bin-2021.20210325.svn15093-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-lollipop-bin-2021.20210325.svn41465-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ltxfileinfo-bin-2021.20210325.svn29005-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ltximg-bin-2021.20210325.svn32346-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-luahbtex-bin-2021.20210325.svn58535-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-luajittex-bin-2021.20210325.svn58535-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-luaotfload-bin-2021.20210325.svn34647-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-luatex-bin-2021.20210325.svn58535-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-lwarp-bin-2021.20210325.svn43292-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-m-tx-bin-2021.20210325.svn50281-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-make4ht-bin-2021.20210325.svn37750-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-makedtx-bin-2021.20210325.svn38769-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-makeindex-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-match_parens-bin-2021.20210325.svn23500-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mathspic-bin-2021.20210325.svn23661-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-metafont-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-metapost-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mex-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mf2pt1-bin-2021.20210325.svn23406-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mflua-bin-2021.20210325.svn58535-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mfware-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mkgrkindex-bin-2021.20210325.svn14428-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mkjobtexmf-bin-2021.20210325.svn8457-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mkpic-bin-2021.20210325.svn33688-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mltex-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-mptopdf-bin-2021.20210325.svn18674-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-multibibliography-bin-2021.20210325.svn30534-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-musixtex-bin-2021.20210325.svn37026-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-musixtnt-bin-2021.20210325.svn50281-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-omegaware-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-optex-bin-2021.20210325.svn53804-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-patgen-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pax-bin-2021.20210325.svn10843-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdfbook2-bin-2021.20210325.svn37537-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdfcrop-bin-2021.20210325.svn14387-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdfjam-bin-2021.20210325.svn52858-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdflatexpicscale-bin-2021.20210325.svn41779-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdftex-bin-2021.20210325.svn58535-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdftex-quiet-bin-2021.20210325.svn49140-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdftosrc-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pdfxup-bin-2021.20210325.svn40690-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pedigree-perl-bin-2021.20210325.svn25962-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-perltex-bin-2021.20210325.svn16181-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-petri-nets-bin-2021.20210325.svn39165-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pfarrei-bin-2021.20210325.svn29348-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pkfix-bin-2021.20210325.svn13364-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pkfix-helper-bin-2021.20210325.svn13663-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-platex-bin-2021.20210325.svn52800-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pmxchords-bin-2021.20210325.svn32405-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ps2eps-bin-2021.20210325.svn50281-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ps2pk-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pst-pdf-bin-2021.20210325.svn7838-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pst2pdf-bin-2021.20210325.svn29333-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ptex-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ptex-fontmaps-bin-2021.20210325.svn44206-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ptex2pdf-bin-2021.20210325.svn29335-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ptexenc-devel-1.3.9-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-purifyeps-bin-2021.20210325.svn13663-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pygmentex-bin-2021.20210325.svn34996-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-pythontex-bin-2021.20210325.svn31638-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-rubik-bin-2021.20210325.svn32919-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-scripts-bin-2021.20210325.svn55172-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-scripts-extra-bin-2021.20210325.svn53577-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-seetexk-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-spix-bin-2021.20210325.svn55933-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-splitindex-bin-2021.20210325.svn29688-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-srcredact-bin-2021.20210325.svn38710-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-sty2dtx-bin-2021.20210325.svn21215-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-svn-multi-bin-2021.20210325.svn13663-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-synctex-bin-2021.20210325.svn58136-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-synctex-devel-1.21-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-tex-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-tex4ebook-bin-2021.20210325.svn37771-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-tex4ht-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texcount-bin-2021.20210325.svn13013-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texdef-bin-2021.20210325.svn45011-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texdiff-bin-2021.20210325.svn15506-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texdirflatten-bin-2021.20210325.svn12782-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texdoc-bin-2021.20210325.svn47948-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texdoctk-bin-2021.20210325.svn29741-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texfot-bin-2021.20210325.svn33155-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texliveonfly-bin-2021.20210325.svn24062-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texloganalyser-bin-2021.20210325.svn13663-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texlua-devel-5.3.6-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'cpu':'aarch64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texluajit-devel-2.1.0beta3-150400.31.6.4', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texosquery-bin-2021.20210325.svn43596-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texplate-bin-2021.20210325.svn53444-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texsis-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-texware-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-thumbpdf-bin-2021.20210325.svn6898-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-tie-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-tikztosvg-bin-2021.20210325.svn55132-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-tpic2pdftex-bin-2021.20210325.svn50281-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ttfutils-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-typeoutfileinfo-bin-2021.20210325.svn25648-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-ulqda-bin-2021.20210325.svn13663-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-uplatex-bin-2021.20210325.svn52800-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-uptex-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-urlbst-bin-2021.20210325.svn23262-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-velthuis-bin-2021.20210325.svn50281-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-vlna-bin-2021.20210325.svn50281-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-vpe-bin-2021.20210325.svn6897-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-web-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-webquiz-bin-2021.20210325.svn50419-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-wordcount-bin-2021.20210325.svn46165-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-xdvi-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-xelatex-dev-bin-2021.20210325.svn53999-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-xetex-bin-2021.20210325.svn58378-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-xindex-bin-2021.20210325.svn49312-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-xml2pmx-bin-2021.20210325.svn57878-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-xmltex-bin-2021.20210325.svn3006-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-xpdfopen-bin-2021.20210325.svn52917-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'texlive-yplan-bin-2021.20210325.svn34398-150400.31.6.4', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libkpathsea6 / libptexenc1 / libsynctex2 / libtexlua53-5 / etc');
}
