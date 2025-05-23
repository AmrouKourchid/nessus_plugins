#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2372-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140540);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/20");

  script_cve_id("CVE-2020-25219");

  script_name(english:"Debian DLA-2372-1 : libproxy security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It was discovered that there was a denial of service attack in
libproxy, a library to make applications HTTP proxy aware. A remote
server could cause an infinite stack recursion.

For Debian 9 'Stretch', this problem has been fixed in version
0.4.14-2+deb9u1.

We recommend that you upgrade your libproxy packages.

For the detailed security status of libproxy please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libproxy

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/09/msg00012.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libproxy");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libproxy");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25219");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy-cil-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy0.4-cil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy1-plugin-gsettings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy1-plugin-kconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy1-plugin-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy1-plugin-networkmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy1-plugin-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy1v5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libproxy");
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
if (deb_check(release:"9.0", prefix:"libproxy-cil-dev", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy-dev", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy-tools", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy0.4-cil", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy1-plugin-gsettings", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy1-plugin-kconfig", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy1-plugin-mozjs", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy1-plugin-networkmanager", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy1-plugin-webkit", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libproxy1v5", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-libproxy", reference:"0.4.14-2+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-libproxy", reference:"0.4.14-2+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
