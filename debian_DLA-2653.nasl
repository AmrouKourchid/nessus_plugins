#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2653-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149372);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id(
    "CVE-2021-3516",
    "CVE-2021-3517",
    "CVE-2021-3518",
    "CVE-2021-3537"
  );

  script_name(english:"Debian DLA-2653-1 : libxml2 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were discovered in libxml2, a library
providing support to read, modify and write XML and HTML files, which
could cause denial of service via application crash when parsing
specially crafted files.

For Debian 9 stretch, these problems have been fixed in version
2.9.4+dfsg1-2.2+deb9u4.

We recommend that you upgrade your libxml2 packages.

For the detailed security status of libxml2 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/libxml2

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00008.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libxml2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libxml2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3517");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3518");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxml2-utils-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-libxml2-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"9.0", prefix:"libxml2", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-dbg", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-dev", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-doc", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-utils", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"libxml2-utils-dbg", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python-libxml2", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python-libxml2-dbg", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3-libxml2", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"python3-libxml2-dbg", reference:"2.9.4+dfsg1-2.2+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
