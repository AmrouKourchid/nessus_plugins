#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1551-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118240);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/30");

  script_cve_id("CVE-2018-10958", "CVE-2018-10999", "CVE-2018-16336");

  script_name(english:"Debian DLA-1551-1 : exiv2 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A vulnerability has been discovered in exiv2 (CVE-2018-16336), a C++
library and a command line utility to manage image metadata, resulting
in remote denial of service (heap-based buffer over-read/overflow) via
a crafted image file.

Additionally, this update includes a minor change to the patch for the
CVE-2018-10958/CVE-2018-10999 vulnerability first addressed in DLA
1402-1. The initial patch was overly restrictive and has been adjusted
to remove the excessive restriction.

For Debian 8 'Jessie', these problems have been fixed in version
0.24-4.1+deb8u2.

We recommend that you upgrade your exiv2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/10/msg00012.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/exiv2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-13");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libexiv2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"exiv2", reference:"0.24-4.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libexiv2-13", reference:"0.24-4.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libexiv2-dbg", reference:"0.24-4.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libexiv2-dev", reference:"0.24-4.1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libexiv2-doc", reference:"0.24-4.1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
