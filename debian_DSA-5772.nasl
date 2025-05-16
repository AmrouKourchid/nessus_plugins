#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5772. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(207365);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/17");

  script_cve_id("CVE-2024-7788");

  script_name(english:"Debian dsa-5772 : fonts-opensymbol - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by a vulnerability as referenced in the dsa-5772
advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5772-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    September 17, 2024                    https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : libreoffice
    CVE ID         : CVE-2024-7788

    Yufan You discovered that Libreoffice's handling of documents based on
    ZIP archives was suspectible to spoofing attacks when the repair mode
    attempts to address a malformed archive structure.

    For additional information please refer to
    https://www.libreoffice.org/about-us/security/advisories/cve-2024-7788/

    For the stable distribution (bookworm), this problem has been fixed in
    version 4:7.4.7-1+deb12u5.

    We recommend that you upgrade your libreoffice packages.

    For the detailed security status of libreoffice please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/libreoffice

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libreoffice");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-7788");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/libreoffice");
  script_set_attribute(attribute:"solution", value:
"Upgrade the fonts-opensymbol packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7788");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fonts-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-lokdocview-0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblibreoffice-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblibreofficekitgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libofficebean-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-base-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-base-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-calc-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-core-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-dev-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-dev-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-dev-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-draw-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-impress-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-kf5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-gug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-kmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-math-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-plasma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-report-builder-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-report-builder-bin-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-script-provider-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-script-provider-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-script-provider-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-sdbc-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-sdbc-hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-sdbc-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-sdbc-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-smoketest-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-colibre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-elementary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-karasa-jaga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-sukapura");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-subsequentcheckbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-writer-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreofficekit-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreofficekit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuno-cppu3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuno-cppuhelpergcc3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuno-purpenvhelpergcc3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuno-sal3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libuno-salhelpergcc3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libunoloader-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-access2base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uno-libs-private");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ure-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'fonts-opensymbol', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'gir1.2-lokdocview-0.1', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'liblibreoffice-java', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'liblibreofficekitgtk', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libofficebean-java', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-base', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-base-core', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-base-drivers', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-base-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-calc', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-calc-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-common', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-core', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-core-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-dev', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-dev-common', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-dev-doc', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-dev-gui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-draw', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-draw-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-evolution', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-gnome', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-gtk3', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-ca', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-common', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-cs', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-da', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-de', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-dz', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-el', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-en-gb', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-en-us', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-es', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-et', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-eu', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-fi', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-fr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-gl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-hi', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-hu', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-id', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-it', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-ja', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-km', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-ko', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-nl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-om', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-pl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-pt', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-pt-br', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-ru', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-sk', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-sl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-sv', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-tr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-vi', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-zh-cn', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-help-zh-tw', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-impress', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-impress-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-java-common', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-kf5', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-af', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-am', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ar', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-as', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ast', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-be', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-bg', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-bn', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-br', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-bs', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ca', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-cs', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-cy', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-da', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-de', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-dz', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-el', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-en-gb', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-en-za', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-eo', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-es', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-et', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-eu', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-fa', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-fi', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-fr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ga', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-gd', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-gl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-gu', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-gug', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-he', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-hi', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-hr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-hu', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-id', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-in', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-is', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-it', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ja', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ka', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-kk', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-km', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-kmr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-kn', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ko', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-lt', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-lv', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-mk', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ml', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-mn', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-mr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-nb', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ne', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-nl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-nn', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-nr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-nso', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-oc', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-om', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-or', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-pa-in', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-pl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-pt', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-pt-br', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ro', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ru', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-rw', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-si', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-sk', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-sl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-sr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ss', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-st', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-sv', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-szl', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ta', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-te', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-tg', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-th', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-tn', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-tr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ts', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ug', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-uk', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-uz', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-ve', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-vi', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-xh', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-za', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-zh-cn', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-zh-tw', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-l10n-zu', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-librelogo', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-math', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-math-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-nlpsolver', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-plasma', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-qt5', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-report-builder', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-report-builder-bin', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-report-builder-bin-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-script-provider-bsh', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-script-provider-js', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-script-provider-python', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-sdbc-firebird', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-sdbc-hsqldb', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-sdbc-mysql', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-sdbc-postgresql', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-smoketest-data', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-style-breeze', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-style-colibre', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-style-elementary', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-style-karasa-jaga', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-style-sifr', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-style-sukapura', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-subsequentcheckbase', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-wiki-publisher', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-writer', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreoffice-writer-nogui', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreofficekit-data', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libreofficekit-dev', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libuno-cppu3', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libuno-cppuhelpergcc3-3', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libuno-purpenvhelpergcc3-3', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libuno-sal3', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libuno-salhelpergcc3-3', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'libunoloader-java', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'python3-access2base', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'python3-uno', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'uno-libs-private', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'ure', 'reference': '4:7.4.7-1+deb12u5'},
    {'release': '12.0', 'prefix': 'ure-java', 'reference': '4:7.4.7-1+deb12u5'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fonts-opensymbol / gir1.2-lokdocview-0.1 / liblibreoffice-java / etc');
}
