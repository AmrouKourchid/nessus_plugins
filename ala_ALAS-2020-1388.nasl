#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2020-1388.
#

include('compat.inc');

if (description)
{
  script_id(138059);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2018-17407");
  script_xref(name:"ALAS", value:"2020-1388");

  script_name(english:"Amazon Linux AMI : texlive (ALAS-2020-1388)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of texlive installed on the remote host is prior to 2012-45.20130427_r30134. It is, therefore, affected by a
vulnerability as referenced in the ALAS-2020-1388 advisory.

    An issue was discovered in t1_check_unusual_charstring functions in writet1.c files in TeX Live before
    2018-09-21. A buffer overflow in the handling of Type 1 fonts allows arbitrary code execution when a
    malicious font is loaded by one of the vulnerable tools: pdflatex, pdftex, dvips, or luatex.
    (CVE-2018-17407)

Tenable has extracted the preceding description block directly from the tested product security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2018-17407");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2020-1388.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update texlive' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17407");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-adjustbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-adjustbox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ae-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-algorithms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-algorithms-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-amscls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-amscls-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-amsfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-amsfonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-amsmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-amsmath-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-anysize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-anysize-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-appendix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-appendix-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-arabxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-arabxetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-arphic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-arphic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-attachfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-attachfile-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-avantgar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-babel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-babel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-babelbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-babelbib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-beamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-beamer-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bera-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-beton");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-beton-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bibtex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bibtex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bibtex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bibtopic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bibtopic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bidi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bidi-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bigfoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bigfoot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-bookman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-booktabs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-booktabs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-breakurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-breakurl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-caption");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-caption-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-carlisle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-carlisle-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-changebar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-changebar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-changepage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-changepage-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-charter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-charter-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-chngcntr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-chngcntr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cjk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cm-lgc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cm-lgc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cm-super");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cm-super-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cmap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cmextra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-cns-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collectbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collectbox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collection-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collection-documentation-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collection-fontsrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collection-htmlxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collection-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collection-latexrecommended");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-collection-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-colortbl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-colortbl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-courier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-crop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-crop-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-csquotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-csquotes-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ctable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ctable-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-currfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-currfile-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-datetime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-datetime-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipdfm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipdfm-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipdfm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipdfmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipdfmx-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipdfmx-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipdfmx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipng-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvipng-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvips-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-dvips-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-eepic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-eepic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-enctex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-enctex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-enumitem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-enumitem-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-epsf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-epsf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-epstopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-epstopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-epstopdf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-eso-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-eso-pic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-etex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-etex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-etex-pkg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-etex-pkg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-etoolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-etoolbox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-euenc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-euenc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-euler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-euler-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-euro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-euro-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-eurosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-eurosym-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-extsizes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-extsizes-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancybox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancybox-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancyhdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancyhdr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancyref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancyref-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancyvrb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fancyvrb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-filecontents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-filecontents-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-filehook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-filehook-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fix2col");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fix2col-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fixlatvian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fixlatvian-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-float");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-float-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fmtcount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fmtcount-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fncychap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fncychap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontbook-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontspec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fontwrap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-footmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-footmisc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-fpl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-framed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-framed-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-garuda-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-geometry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-geometry-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-glyphlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-graphics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-graphics-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-gsftopk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-gsftopk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-helvetic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-hyperref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-hyperref-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-hyph-utf8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-hyph-utf8-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-hyphen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-hyphenat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-hyphenat-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifluatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifluatex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifmtarg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifmtarg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifoddpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifoddpage-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-iftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-iftex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifxetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ifxetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-index");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-index-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-jadetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-jadetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-jadetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-jknapltx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-jknapltx-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kastrup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kastrup-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kerkis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kerkis-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-koma-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kpathsea-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kpathsea-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kpathsea-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-kpathsea-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-l3experimental");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-l3experimental-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-l3kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-l3kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-l3packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-l3packages-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lastpage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lastpage-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latex-bin-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latex-fonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-latexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lettrine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lettrine-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-listings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-listings-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lm-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lm-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ltxmisc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lua-alt-getopt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lua-alt-getopt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lualatex-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-lualatex-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luaotfload");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luaotfload-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luaotfload-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luatex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luatex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luatexbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-luatexbase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-makecmds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-makecmds-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-makeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-makeindex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-makeindex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-marginnote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-marginnote-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-marvosym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-marvosym-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mathpazo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mathpazo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mathspec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mdwtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mdwtools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-memoir");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-memoir-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metafont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metafont-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metalogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metalogo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metapost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metapost-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metapost-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-metapost-examples-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mflogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mflogo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mfnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mfnfss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mfware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mfware-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mh-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-microtype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-microtype-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-misc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mnsymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mnsymbol-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mparhack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mparhack-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mptopdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-mptopdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ms-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-multido");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-multido-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-multirow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-multirow-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-natbib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-natbib-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ncctools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ncctools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ncntrsbk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-norasi-c90");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ntgclass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ntgclass-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-oberdiek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-oberdiek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-overpic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-overpic-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-palatino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-paralist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-paralist-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-parallel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-parskip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-parskip-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-passivetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pdfpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pdfpages-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pdftex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pdftex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pdftex-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pdftex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pgf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pgf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-philokalia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-philokalia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-placeins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-placeins-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-plain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-polyglossia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-polyglossia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-powerdot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-powerdot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-preprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-preprint-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-psfrag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-psfrag-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pslatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-psnfss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-psnfss-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pspicture");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pspicture-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-3d-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-blur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-blur-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-coil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-coil-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-eps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-eps-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-fill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-fill-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-grad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-grad-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-node-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-plot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-plot-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-slpe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-slpe-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-text-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pst-tree-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pstricks-add");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pstricks-add-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pstricks-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ptext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ptext-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pxfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-pxfonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-qstest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-qstest-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-rcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-rcs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-realscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-realscripts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-rotating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-rotating-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-rsfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-rsfs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sansmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sansmath-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sauerj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sauerj-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-scheme-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-section");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-section-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sectsty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sectsty-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-seminar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-seminar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sepnum");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-sepnum-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-setspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-setspace-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-showexpl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-showexpl-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-soul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-soul-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-stmaryrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-stmaryrd-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-subfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-subfig-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-subfigure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-subfigure-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-svn-prov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-svn-prov-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-symbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-t2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-t2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex-gyre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex-gyre-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex-gyre-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex-gyre-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex4ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex4ht-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tex4ht-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-texconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-texconfig-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-texlive.infra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-texlive.infra-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-texlive.infra-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-textcase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-textcase-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-textpos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-textpos-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-thailatex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-thailatex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-threeparttable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-threeparttable-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-thumbpdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-thumbpdf-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-thumbpdf-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-times");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tipa-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-titlesec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-titlesec-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-titling");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-titling-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tocloft");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tocloft-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-tools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-txfonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-txfonts-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-type1cm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-type1cm-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-typehtml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-typehtml-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ucharclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ucharclasses-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ucs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ucs-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-uhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-uhc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ulem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-ulem-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-underscore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-underscore-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-unicode-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-unicode-math-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-unisugar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-unisugar-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-url");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-url-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-utopia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-utopia-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-varwidth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-varwidth-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wadalab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wadalab-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-was");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-was-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wasy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wasy-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wasysym");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wasysym-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wrapfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-wrapfig-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xcolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xcolor-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xdvi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xdvi-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xecjk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xecjk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xecolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xecolor-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xecyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xecyr-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xeindex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xeindex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xepersian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xepersian-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xesearch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xesearch-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-def");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-itrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-itrans-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-pstricks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-pstricks-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-tibetan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetex-tibetan-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetexconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetexfontinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xetexfontinfo-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xifthen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xifthen-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xkeyval");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xkeyval-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xltxtra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xltxtra-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xmltex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xmltex-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xmltex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xstring-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xtab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xtab-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xunicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-xunicode-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-zapfchan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:texlive-zapfding");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var alas_release = get_kb_item("Host/AmazonLinux/release");
if (isnull(alas_release) || !strlen(alas_release)) audit(AUDIT_OS_NOT, "Amazon Linux");
var os_ver = pregmatch(pattern: "^AL(A|\d+|-\d+)", string:alas_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var pkgs = [
    {'reference':'texlive-2012-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-2012-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-adjustbox-doc-svn26555.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-adjustbox-svn26555.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ae-doc-svn15878.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ae-svn15878.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-algorithms-doc-svn15878.0.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-algorithms-svn15878.0.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-amscls-doc-svn29207.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-amscls-svn29207.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-amsfonts-doc-svn29208.3.04-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-amsfonts-svn29208.3.04-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-amsmath-doc-svn29327.2.14-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-amsmath-svn29327.2.14-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-anysize-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-anysize-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-appendix-doc-svn15878.1.2b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-appendix-svn15878.1.2b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-arabxetex-doc-svn17470.v1.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-arabxetex-svn17470.v1.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-arphic-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-arphic-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-attachfile-doc-svn21866.v1.5b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-attachfile-svn21866.v1.5b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-avantgar-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-babel-doc-svn24756.3.8m-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-babel-svn24756.3.8m-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-babelbib-doc-svn25245.1.31-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-babelbib-svn25245.1.31-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-base-2012-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-beamer-doc-svn29349.3.26-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-beamer-svn29349.3.26-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bera-doc-svn20031.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bera-svn20031.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-beton-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-beton-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bibtex-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bibtex-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bibtex-doc-svn26689.0.99d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bibtex-svn26689.0.99d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bibtopic-doc-svn15878.1.1a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bibtopic-svn15878.1.1a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bidi-doc-svn29650.12.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bidi-svn29650.12.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bigfoot-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bigfoot-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-bookman-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-booktabs-doc-svn15878.1.61803-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-booktabs-svn15878.1.61803-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-breakurl-doc-svn15878.1.30-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-breakurl-svn15878.1.30-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-caption-doc-svn29026.3.3__2013_02_03_-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-caption-svn29026.3.3__2013_02_03_-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-carlisle-doc-svn18258.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-carlisle-svn18258.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-changebar-doc-svn29349.3.5c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-changebar-svn29349.3.5c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-changepage-doc-svn15878.1.0c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-changepage-svn15878.1.0c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-charter-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-charter-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-chngcntr-doc-svn17157.1.0a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-chngcntr-svn17157.1.0a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cite-doc-svn19955.5.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cite-svn19955.5.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cjk-doc-svn26296.4.8.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cjk-svn26296.4.8.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cm-doc-svn29581.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cm-lgc-doc-svn28250.0.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cm-lgc-svn28250.0.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cm-super-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cm-super-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cm-svn29581.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cmap-doc-svn26568.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cmap-svn26568.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cmextra-svn14075.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cns-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-cns-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collectbox-doc-svn26557.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collectbox-svn26557.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collection-basic-svn26314.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collection-documentation-base-svn17091.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collection-fontsrecommended-svn28082.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collection-htmlxml-svn28251.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collection-latex-svn25030.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collection-latexrecommended-svn25795.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-collection-xetex-svn29634.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-colortbl-doc-svn25394.v1.0a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-colortbl-svn25394.v1.0a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-courier-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-crop-doc-svn15878.1.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-crop-svn15878.1.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-csquotes-doc-svn24393.5.1d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-csquotes-svn24393.5.1d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ctable-doc-svn26694.1.23-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ctable-svn26694.1.23-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-currfile-doc-svn29012.0.7b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-currfile-svn29012.0.7b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-datetime-doc-svn19834.2.58-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-datetime-svn19834.2.58-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-debuginfo-2012-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-debuginfo-2012-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfm-bin-svn13663.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfm-doc-svn26689.0.13.2d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfm-svn26689.0.13.2d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfmx-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfmx-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfmx-def-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfmx-doc-svn26765.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipdfmx-svn26765.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipng-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipng-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipng-doc-svn26689.1.14-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvipng-svn26689.1.14-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvips-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvips-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvips-doc-svn29585.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-dvips-svn29585.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ec-doc-svn25033.1.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ec-svn25033.1.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-eepic-doc-svn15878.1.1e-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-eepic-svn15878.1.1e-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-enctex-doc-svn28602.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-enctex-svn28602.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-enumitem-doc-svn24146.3.5.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-enumitem-svn24146.3.5.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-epsf-doc-svn21461.2.7.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-epsf-svn21461.2.7.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-epstopdf-bin-svn18336.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-epstopdf-doc-svn26577.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-epstopdf-svn26577.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-eso-pic-doc-svn21515.2.0c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-eso-pic-svn21515.2.0c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-etex-doc-svn22198.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-etex-pkg-doc-svn15878.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-etex-pkg-svn15878.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-etex-svn22198.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-etoolbox-doc-svn20922.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-etoolbox-svn20922.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-euenc-doc-svn19795.0.1h-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-euenc-svn19795.0.1h-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-euler-doc-svn17261.2.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-euler-svn17261.2.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-euro-doc-svn22191.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-euro-svn22191.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-eurosym-doc-svn17265.1.4_subrfix-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-eurosym-svn17265.1.4_subrfix-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-extsizes-doc-svn17263.1.4a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-extsizes-svn17263.1.4a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancybox-doc-svn18304.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancybox-svn18304.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancyhdr-doc-svn15878.3.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancyhdr-svn15878.3.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancyref-doc-svn15878.0.9c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancyref-svn15878.0.9c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancyvrb-doc-svn18492.2.8-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fancyvrb-svn18492.2.8-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-filecontents-doc-svn24250.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-filecontents-svn24250.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-filehook-doc-svn24280.0.5d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-filehook-svn24280.0.5d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fix2col-doc-svn17133.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fix2col-svn17133.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fixlatvian-doc-svn21631.1a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fixlatvian-svn21631.1a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-float-doc-svn15878.1.3d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-float-svn15878.1.3d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fmtcount-doc-svn28068.2.02-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fmtcount-svn28068.2.02-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fncychap-doc-svn20710.v1.34-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fncychap-svn20710.v1.34-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontbook-doc-svn23608.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontbook-svn23608.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontspec-doc-svn29412.v2.3a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontspec-svn29412.v2.3a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontware-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontware-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontware-svn26689.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontwrap-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fontwrap-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-footmisc-doc-svn23330.5.5b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-footmisc-svn23330.5.5b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fp-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fp-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fpl-doc-svn15878.1.002-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-fpl-svn15878.1.002-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-framed-doc-svn26789.0.96-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-framed-svn26789.0.96-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-garuda-c90-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-geometry-doc-svn19716.5.6-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-geometry-svn19716.5.6-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-glyphlist-svn28576.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-graphics-doc-svn25405.1.0o-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-graphics-svn25405.1.0o-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-gsftopk-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-gsftopk-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-gsftopk-svn26689.1.19.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-helvetic-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-hyperref-doc-svn28213.6.83m-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-hyperref-svn28213.6.83m-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-hyph-utf8-doc-svn29641.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-hyph-utf8-svn29641.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-hyphen-base-svn29197.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-hyphenat-doc-svn15878.2.3c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-hyphenat-svn15878.2.3c-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifetex-doc-svn24853.1.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifetex-svn24853.1.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifluatex-doc-svn26725.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifluatex-svn26725.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifmtarg-doc-svn19363.1.2a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifmtarg-svn19363.1.2a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifoddpage-doc-svn23979.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifoddpage-svn23979.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-iftex-doc-svn29654.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-iftex-svn29654.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifxetex-doc-svn19685.0.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ifxetex-svn19685.0.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-index-doc-svn24099.4.1beta-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-index-svn24099.4.1beta-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-jadetex-bin-svn3006.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-jadetex-doc-svn23409.3.13-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-jadetex-svn23409.3.13-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-jknapltx-doc-svn19440.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-jknapltx-svn19440.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kastrup-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kastrup-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kerkis-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kerkis-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-koma-script-svn27255.3.11b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-bin-svn27347.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-bin-svn27347.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-doc-svn28792.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-lib-2012-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-lib-2012-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-lib-devel-2012-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-lib-devel-2012-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-kpathsea-svn28792.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-l3experimental-doc-svn29361.SVN_4467-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-l3experimental-svn29361.SVN_4467-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-l3kernel-doc-svn29409.SVN_4469-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-l3kernel-svn29409.SVN_4469-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-l3packages-doc-svn29361.SVN_4467-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-l3packages-svn29361.SVN_4467-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lastpage-doc-svn28985.1.2l-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lastpage-svn28985.1.2l-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-latex-bin-bin-svn14050.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-latex-bin-svn26689.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-latex-doc-svn27907.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-latex-fonts-doc-svn28888.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-latex-fonts-svn28888.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-latex-svn27907.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-latexconfig-svn28991.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lettrine-doc-svn29391.1.64-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lettrine-svn29391.1.64-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-listings-doc-svn15878.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-listings-svn15878.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lm-doc-svn28119.2.004-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lm-math-doc-svn29044.1.958-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lm-math-svn29044.1.958-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lm-svn28119.2.004-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ltxmisc-svn21927.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lua-alt-getopt-doc-svn29349.0.7.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lua-alt-getopt-svn29349.0.7.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lualatex-math-doc-svn29346.1.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-lualatex-math-svn29346.1.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luaotfload-bin-svn18579.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luaotfload-doc-svn26718.1.26-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luaotfload-svn26718.1.26-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luatex-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luatex-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luatex-doc-svn26689.0.70.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luatex-svn26689.0.70.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luatexbase-doc-svn22560.0.31-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-luatexbase-svn22560.0.31-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-makecmds-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-makecmds-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-makeindex-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-makeindex-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-makeindex-doc-svn26689.2.12-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-makeindex-svn26689.2.12-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-marginnote-doc-svn25880.v1.1i-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-marginnote-svn25880.v1.1i-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-marvosym-doc-svn29349.2.2a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-marvosym-svn29349.2.2a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mathpazo-doc-svn15878.1.003-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mathpazo-svn15878.1.003-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mathspec-doc-svn15878.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mathspec-svn15878.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mdwtools-doc-svn15878.1.05.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mdwtools-svn15878.1.05.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-memoir-doc-svn21638.3.6j_patch_6.0g-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-memoir-svn21638.3.6j_patch_6.0g-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metafont-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metafont-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metafont-svn26689.2.718281-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metalogo-doc-svn18611.0.12-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metalogo-svn18611.0.12-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metapost-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metapost-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metapost-doc-svn26689.1.212-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metapost-examples-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-metapost-svn26689.1.212-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mflogo-doc-svn17487.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mflogo-svn17487.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mfnfss-doc-svn19410.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mfnfss-svn19410.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mfware-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mfware-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mfware-svn26689.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mh-doc-svn29420.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mh-svn29420.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-microtype-doc-svn29392.2.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-microtype-svn29392.2.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-misc-svn24955.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mnsymbol-doc-svn18651.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mnsymbol-svn18651.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mparhack-doc-svn15878.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mparhack-svn15878.1.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mptopdf-bin-svn18674.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-mptopdf-svn26689.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ms-doc-svn24467.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ms-svn24467.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-multido-doc-svn18302.1.42-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-multido-svn18302.1.42-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-multirow-doc-svn17256.1.6-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-multirow-svn17256.1.6-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-natbib-doc-svn20668.8.31b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-natbib-svn20668.8.31b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ncctools-doc-svn15878.3.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ncctools-svn15878.3.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ncntrsbk-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-norasi-c90-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ntgclass-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ntgclass-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-oberdiek-doc-svn26725.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-oberdiek-svn26725.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-overpic-doc-svn19712.0.53-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-overpic-svn19712.0.53-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-palatino-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-paralist-doc-svn15878.2.3b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-paralist-svn15878.2.3b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-parallel-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-parallel-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-parskip-doc-svn19963.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-parskip-svn19963.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-passivetex-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pdfpages-doc-svn27574.0.4t-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pdfpages-svn27574.0.4t-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pdftex-bin-svn27321.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pdftex-bin-svn27321.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pdftex-def-svn22653.0.06d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pdftex-doc-svn29585.1.40.11-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pdftex-svn29585.1.40.11-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pgf-doc-svn22614.2.10-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pgf-svn22614.2.10-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-philokalia-doc-svn18651.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-philokalia-svn18651.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-placeins-doc-svn19848.2.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-placeins-svn19848.2.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-plain-svn26647.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-polyglossia-doc-svn26163.v1.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-polyglossia-svn26163.v1.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-powerdot-doc-svn25656.1.4i-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-powerdot-svn25656.1.4i-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-preprint-doc-svn16085.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-preprint-svn16085.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-psfrag-doc-svn15878.3.04-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-psfrag-svn15878.3.04-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pslatex-svn16416.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-psnfss-doc-svn23394.9.2a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-psnfss-svn23394.9.2a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pspicture-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pspicture-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-3d-doc-svn17257.1.10-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-3d-svn17257.1.10-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-blur-doc-svn15878.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-blur-svn15878.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-coil-doc-svn24020.1.06-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-coil-svn24020.1.06-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-eps-doc-svn15878.1.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-eps-svn15878.1.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-fill-doc-svn15878.1.01-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-fill-svn15878.1.01-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-grad-doc-svn15878.1.06-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-grad-svn15878.1.06-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-math-doc-svn20176.0.61-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-math-svn20176.0.61-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-node-doc-svn27799.1.25-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-node-svn27799.1.25-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-plot-doc-svn28729.1.44-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-plot-svn28729.1.44-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-slpe-doc-svn24391.1.31-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-slpe-svn24391.1.31-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-text-doc-svn15878.1.00-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-text-svn15878.1.00-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-tree-doc-svn24142.1.12-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pst-tree-svn24142.1.12-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pstricks-add-doc-svn28750.3.59-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pstricks-add-svn28750.3.59-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pstricks-doc-svn29678.2.39-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pstricks-svn29678.2.39-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ptext-doc-svn28124.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ptext-svn28124.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pxfonts-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-pxfonts-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-qstest-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-qstest-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-rcs-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-rcs-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-realscripts-doc-svn29423.0.3b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-realscripts-svn29423.0.3b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-rotating-doc-svn16832.2.16b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-rotating-svn16832.2.16b-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-rsfs-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-rsfs-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sansmath-doc-svn17997.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sansmath-svn17997.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sauerj-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sauerj-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-scheme-basic-svn25923.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-section-doc-svn20180.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-section-svn20180.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sectsty-doc-svn15878.2.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sectsty-svn15878.2.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-seminar-doc-svn18322.1.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-seminar-svn18322.1.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sepnum-doc-svn20186.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-sepnum-svn20186.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-setspace-doc-svn24881.6.7a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-setspace-svn24881.6.7a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-showexpl-doc-svn27790.v0.3j-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-showexpl-svn27790.v0.3j-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-soul-doc-svn15878.2.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-soul-svn15878.2.4-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-stmaryrd-doc-svn22027.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-stmaryrd-svn22027.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-subfig-doc-svn15878.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-subfig-svn15878.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-subfigure-doc-svn15878.2.1.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-subfigure-svn15878.2.1.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-svn-prov-doc-svn18017.3.1862-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-svn-prov-svn18017.3.1862-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-symbol-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-t2-doc-svn29349.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-t2-svn29349.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tetex-bin-svn27344.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tetex-doc-svn29585.3.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tetex-svn29585.3.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex-gyre-doc-svn18651.2.004-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex-gyre-math-doc-svn29045.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex-gyre-math-svn29045.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex-gyre-svn18651.2.004-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex-svn26689.3.1415926-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex4ht-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex4ht-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex4ht-doc-svn29474.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tex4ht-svn29474.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-texconfig-bin-svn27344.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-texconfig-svn29349.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-texlive.infra-bin-svn22566.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-texlive.infra-bin-svn22566.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-texlive.infra-doc-svn28217.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-texlive.infra-svn28217.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-textcase-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-textcase-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-textpos-doc-svn28261.1.7h-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-textpos-svn28261.1.7h-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-thailatex-doc-svn29349.0.5.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-thailatex-svn29349.0.5.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-threeparttable-doc-svn17383.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-threeparttable-svn17383.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-thumbpdf-bin-svn6898.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-thumbpdf-doc-svn26689.3.15-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-thumbpdf-svn26689.3.15-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-times-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tipa-doc-svn29349.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tipa-svn29349.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-titlesec-doc-svn24852.2.10.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-titlesec-svn24852.2.10.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-titling-doc-svn15878.2.1d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-titling-svn15878.2.1d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tocloft-doc-svn20084.2.3e-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tocloft-svn20084.2.3e-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tools-doc-svn26263.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-tools-svn26263.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-txfonts-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-txfonts-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-type1cm-doc-svn21820.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-type1cm-svn21820.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-typehtml-doc-svn17134.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-typehtml-svn17134.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ucharclasses-doc-svn27820.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ucharclasses-svn27820.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ucs-doc-svn27549.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ucs-svn27549.2.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-uhc-doc-svn16791.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-uhc-svn16791.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ulem-doc-svn26785.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-ulem-svn26785.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-underscore-doc-svn18261.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-underscore-svn18261.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-unicode-math-doc-svn29413.0.7d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-unicode-math-svn29413.0.7d-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-unisugar-doc-svn22357.0.92-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-unisugar-svn22357.0.92-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-url-doc-svn16864.3.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-url-svn16864.3.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-utopia-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-utopia-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-varwidth-doc-svn24104.0.92-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-varwidth-svn24104.0.92-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wadalab-doc-svn22576.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wadalab-svn22576.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-was-doc-svn21439.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-was-svn21439.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wasy-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wasy-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wasysym-doc-svn15878.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wasysym-svn15878.2.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wrapfig-doc-svn22048.3.6-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-wrapfig-svn22048.3.6-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xcolor-doc-svn15878.2.11-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xcolor-svn15878.2.11-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xdvi-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xdvi-bin-svn26509.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xdvi-svn26689.22.85-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xecjk-doc-svn28816.3.1.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xecjk-svn28816.3.1.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xecolor-doc-svn29660.0.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xecolor-svn29660.0.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xecyr-doc-svn20221.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xecyr-svn20221.1.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xeindex-doc-svn16760.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xeindex-svn16760.0.2-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xepersian-doc-svn29661.12.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xepersian-svn29661.12.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xesearch-doc-svn16041.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xesearch-svn16041.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'i686', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-bin-svn26912.0-45.20130427_r30134.amzn1', 'cpu':'x86_64', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-def-svn29154.0.95-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-doc-svn26330.0.9997.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-itrans-doc-svn24105.4.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-itrans-svn24105.4.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-pstricks-doc-svn17055.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-pstricks-svn17055.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-svn26330.0.9997.5-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-tibetan-doc-svn28847.0.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetex-tibetan-svn28847.0.1-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetexconfig-svn28819.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetexfontinfo-doc-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xetexfontinfo-svn15878.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xifthen-doc-svn15878.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xifthen-svn15878.1.3-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xkeyval-doc-svn27995.2.6a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xkeyval-svn27995.2.6a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xltxtra-doc-svn19809.0.5e-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xltxtra-svn19809.0.5e-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xmltex-bin-svn3006.0-45.20130427_r30134.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xmltex-doc-svn28273.0.8-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xmltex-svn28273.0.8-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xstring-doc-svn29258.1.7a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xstring-svn29258.1.7a-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xtab-doc-svn23347.2.3f-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xtab-svn23347.2.3f-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xunicode-doc-svn23897.0.981-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-xunicode-svn23897.0.981-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-zapfchan-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'texlive-zapfding-svn28614.0-45.amzn1', 'release':'ALA', 'rpm_spec_vers_cmp':TRUE}
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
  var exists_check = NULL;
  var cves = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "texlive / texlive-adjustbox / texlive-adjustbox-doc / etc");
}
