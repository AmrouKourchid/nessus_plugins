#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2188-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135980);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/14");

  script_cve_id("CVE-2020-7064", "CVE-2020-7066", "CVE-2020-7067");
  script_xref(name:"IAVA", value:"2020-A-0169-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Debian DLA-2188-1 : php5 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Three issues have been found in php5, a server-side, HTML-embedded
scripting language.

CVE-2020-7064 A one byte out-of-bounds read, which could potentially
lead to information disclosure or crash.

CVE-2020-7066 An URL containing zero (\0) character will be truncated
at it, which may cause some software to make incorrect assumptions and
possibly send some information to a wrong server.

CVE-2020-7067 Using a malformed url-encoded string an Out-of-Bounds
read can occur.

For Debian 8 'Jessie', these problems have been fixed in version
5.6.40+dfsg-0+deb8u11.

We recommend that you upgrade your php5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/04/msg00021.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/php5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7064");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-7067");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-php5filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libphp5-embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-interbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-mysqlnd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-phpdbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-readline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php5-xsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-mod-php5filter", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"libphp5-embed", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php-pear", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cgi", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-cli", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-common", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-curl", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dbg", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-dev", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-enchant", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-fpm", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gd", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-gmp", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-imap", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-interbase", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-intl", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-ldap", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mcrypt", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysql", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-mysqlnd", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-odbc", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pgsql", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-phpdbg", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-pspell", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-readline", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-recode", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-snmp", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sqlite", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-sybase", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-tidy", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xmlrpc", reference:"5.6.40+dfsg-0+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"php5-xsl", reference:"5.6.40+dfsg-0+deb8u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
