#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1669-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122067);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/21");

  script_cve_id("CVE-2018-16858");

  script_name(english:"Debian DLA-1669-1 : libreoffice security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Alex Infuehr discovered a directory traversal vulnerability which
could result in the execution of Python script code when opening a
malformed document.

For Debian 8 'Jessie', this problem has been fixed in version
1:4.3.3-2+deb8u12.

We recommend that you upgrade your libreoffice packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2019/02/msg00014.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/libreoffice");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16858");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LibreOffice Macro Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:browser-plugin-libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fonts-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-avmedia-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-avmedia-backend-vlc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-base-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-dev-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-emailmerge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-help-ca");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-af");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-l10n-ku");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-mysql-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-presentation-minimizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-presenter-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-report-builder-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-script-provider-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-script-provider-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-script-provider-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-sdbc-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-sdbc-hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-sdbc-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-crystal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-style-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-subsequentcheckbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openoffice.org-dtd-officedocument1.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-uno");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"browser-plugin-libreoffice", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"fonts-opensymbol", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-avmedia-backend-gstreamer", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-avmedia-backend-vlc", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-base", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-base-core", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-base-drivers", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-calc", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-common", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-core", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-dbg", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-dev", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-dev-doc", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-draw", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-emailmerge", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-evolution", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-gnome", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-gtk", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-gtk3", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-ca", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-cs", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-da", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-de", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-dz", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-el", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-en-gb", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-en-us", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-es", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-et", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-eu", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-fi", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-fr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-gl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-hi", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-hu", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-it", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-ja", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-km", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-ko", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-nl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-om", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-pl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-pt", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-pt-br", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-ru", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-sk", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-sl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-sv", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-tr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-vi", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-zh-cn", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-help-zh-tw", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-impress", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-java-common", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-kde", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-af", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ar", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-as", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ast", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-be", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-bg", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-bn", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-br", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-bs", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ca", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-cs", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-cy", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-da", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-de", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-dz", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-el", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-en-gb", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-en-za", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-eo", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-es", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-et", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-eu", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-fa", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-fi", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-fr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ga", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-gd", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-gl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-gu", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-he", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-hi", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-hr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-hu", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-id", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-in", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-is", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-it", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ja", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ka", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-kk", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-km", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-kmr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ko", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ku", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-lt", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-lv", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-mk", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ml", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-mn", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-mr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-nb", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ne", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-nl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-nn", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-nr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-nso", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-oc", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-om", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-or", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-pa-in", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-pl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-pt", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-pt-br", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ro", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ru", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-rw", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-si", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-sk", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-sl", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-sr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ss", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-st", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-sv", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ta", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-te", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-tg", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-th", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-tn", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-tr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ts", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ug", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-uk", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-uz", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-ve", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-vi", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-xh", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-za", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-zh-cn", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-zh-tw", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-l10n-zu", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-librelogo", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-math", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-mysql-connector", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-officebean", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-ogltrans", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-pdfimport", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-presentation-minimizer", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-presenter-console", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-report-builder", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-report-builder-bin", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-script-provider-bsh", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-script-provider-js", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-script-provider-python", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-sdbc-firebird", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-sdbc-hsqldb", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-sdbc-postgresql", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-style-crystal", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-style-galaxy", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-style-hicontrast", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-style-oxygen", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-style-sifr", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-style-tango", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-subsequentcheckbase", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-wiki-publisher", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"libreoffice-writer", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"openoffice.org-dtd-officedocument1.0", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"python-uno", reference:"1:4.3.3-2+deb8u12")) flag++;
if (deb_check(release:"8.0", prefix:"python3-uno", reference:"1:4.3.3-2+deb8u12")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
