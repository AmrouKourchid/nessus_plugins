#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2009-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131328);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/09");

  script_cve_id(
    "CVE-2017-17095",
    "CVE-2018-12900",
    "CVE-2018-18661",
    "CVE-2019-17546",
    "CVE-2019-6128"
  );

  script_name(english:"Debian DLA-2009-1 : tiff security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several issues have been found in tiff, a Tag Image File Format
library.

CVE-2019-17546

The RGBA interface contains an integer overflow that might lead to
heap buffer overflow write.

CVE-2019-6128

A memory leak exists due to missing cleanup code.

CVE-2018-18661

In case of exhausted memory there is a NULL pointer dereference in
tiff2bw.

CVE-2018-12900

Fix for heap-based buffer overflow, that could be used to crash an
application or even to execute arbitrary code (with the permission of
the user running this application).

CVE-2017-17095

A crafted tiff file could lead to a heap buffer overflow in pal2rgb.

For Debian 8 'Jessie', these problems have been fixed in version
4.0.3-12.3+deb8u10.

We recommend that you upgrade your tiff packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2019/11/msg00027.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/tiff");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6128");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx5");
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
if (deb_check(release:"8.0", prefix:"libtiff-doc", reference:"4.0.3-12.3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff-opengl", reference:"4.0.3-12.3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff-tools", reference:"4.0.3-12.3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff5", reference:"4.0.3-12.3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libtiff5-dev", reference:"4.0.3-12.3+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"libtiffxx5", reference:"4.0.3-12.3+deb8u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
