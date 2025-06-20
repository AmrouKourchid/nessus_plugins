#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2088-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(133364);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/28");

  script_cve_id("CVE-2019-20387");

  script_name(english:"Debian DLA-2088-1 : libsolv security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"repodata_schema2id in repodata.c in libsolv, a dependency solver
library, had a heap-based buffer over-read via a last schema whose
length could be less than the length of the input schema.

For Debian 8 'Jessie', this problem has been fixed in version
0.6.5-1+deb8u1.

We recommend that you upgrade your libsolv packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/01/msg00034.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/libsolv");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20387");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolv-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolv-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolv0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolv0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolv0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolvext0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolvext0-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsolvext0-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-solv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
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
if (deb_check(release:"8.0", prefix:"libsolv-doc", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolv-perl", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolv-tools", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolv0", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolv0-dbg", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolv0-dev", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolvext0", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolvext0-dbg", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libsolvext0-dev", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python-solv", reference:"0.6.5-1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"python3-solv", reference:"0.6.5-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
