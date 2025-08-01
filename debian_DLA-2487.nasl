#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2487-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144029);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/02");

  script_cve_id("CVE-2020-27350");

  script_name(english:"Debian DLA-2487-1 : apt security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It was discovered that missing input validation in the ar/tar
implementations of APT, the high level package manager, could cause
out-of-bounds reads or infinite loops, resulting in denial of service
when processing malformed deb files.

For Debian 9 stretch, this problem has been fixed in version 1.4.11.

We recommend that you upgrade your apt packages.

For the detailed security status of apt please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/apt

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00013.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/apt");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/apt");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-transport-https");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apt-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-inst2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapt-pkg5.0");
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
if (deb_check(release:"9.0", prefix:"apt", reference:"1.4.11")) flag++;
if (deb_check(release:"9.0", prefix:"apt-doc", reference:"1.4.11")) flag++;
if (deb_check(release:"9.0", prefix:"apt-transport-https", reference:"1.4.11")) flag++;
if (deb_check(release:"9.0", prefix:"apt-utils", reference:"1.4.11")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-inst2.0", reference:"1.4.11")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg-dev", reference:"1.4.11")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg-doc", reference:"1.4.11")) flag++;
if (deb_check(release:"9.0", prefix:"libapt-pkg5.0", reference:"1.4.11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
