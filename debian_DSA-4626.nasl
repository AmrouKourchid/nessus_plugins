#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4626. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133733);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/27");

  script_cve_id(
    "CVE-2019-11045",
    "CVE-2019-11046",
    "CVE-2019-11047",
    "CVE-2019-11049",
    "CVE-2019-11050",
    "CVE-2020-7059",
    "CVE-2020-7060"
  );
  script_xref(name:"DSA", value:"4626");

  script_name(english:"Debian DSA-4626-1 : php7.3 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Multiple security issues were found in PHP, a widely-used open source
general purpose scripting language which could result in information
disclosure, denial of service or incorrect validation of path names.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/php7.3");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/php7.3");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4626");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php7.3 packages.

For the stable distribution (buster), these problems have been fixed
in version 7.3.14-1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11049");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php7.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (deb_check(release:"10.0", prefix:"libapache2-mod-php7.3", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libphp7.3-embed", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-bcmath", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-bz2", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-cgi", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-cli", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-common", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-curl", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-dba", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-dev", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-enchant", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-fpm", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-gd", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-gmp", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-imap", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-interbase", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-intl", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-json", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-ldap", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-mbstring", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-mysql", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-odbc", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-opcache", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-pgsql", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-phpdbg", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-pspell", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-readline", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-recode", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-snmp", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-soap", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-sqlite3", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-sybase", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-tidy", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-xml", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-xmlrpc", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-xsl", reference:"7.3.14-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"php7.3-zip", reference:"7.3.14-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
