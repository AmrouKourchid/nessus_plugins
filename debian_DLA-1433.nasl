#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1433-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111170);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/04");

  script_cve_id("CVE-2015-1239", "CVE-2016-5139");

  script_name(english:"Debian DLA-1433-1 : openjpeg2 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"CVE-2015-1239 Fix for denial of service (process crash) via a crafted
PDF.

CVE-2016-5139 Fix for integer overflows, allowing a denial of service
(heap-based buffer overflow) or possibly have unspecified other impact
via crafted JPEG 2000 data.

For Debian 8 'Jessie', these problems have been fixed in version
2.1.0-2+deb8u4.

We recommend that you upgrade your openjpeg2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00025.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/openjpeg2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5139");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjp3d7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-dec-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip-viewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libopenjpip7");
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
if (deb_check(release:"8.0", prefix:"libopenjp2-7", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dbg", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-7-dev", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp2-tools", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d-tools", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjp3d7", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-dec-server", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-server", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip-viewer", reference:"2.1.0-2+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libopenjpip7", reference:"2.1.0-2+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
