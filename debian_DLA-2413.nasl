#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2413-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141901);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id("CVE-2019-19617", "CVE-2020-26934", "CVE-2020-26935");

  script_name(english:"Debian DLA-2413-1 : phpmyadmin security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were found in package phpmyadmin.

CVE-2019-19617

phpMyAdmin does not escape certain Git information, related to
libraries/classes/Display/GitRevision.php and libraries/classes
/Footer.php.

CVE-2020-26934

A vulnerability was discovered where an attacker can cause an XSS
attack through the transformation feature.

If an attacker sends a crafted link to the victim with the
malicious JavaScript, when the victim clicks on the link,
the JavaScript will run and complete the instructions made
by the attacker.

CVE-2020-26935

A SQL injection vulnerability was discovered in how phpMyAdmin
processes SQL statements in the search feature. An attacker could use
this flaw to inject malicious SQL in to a query.

For Debian 9 stretch, these problems have been fixed in version
4.6.6-4+deb9u2.

We recommend that you upgrade your phpmyadmin packages.

For the detailed security status of phpmyadmin please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/phpmyadmin

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00024.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/phpmyadmin");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/phpmyadmin");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected phpmyadmin package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26935");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:phpmyadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (deb_check(release:"9.0", prefix:"phpmyadmin", reference:"4.6.6-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
