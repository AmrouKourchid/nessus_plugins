#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1526-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(117836);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/01");

  script_cve_id("CVE-2018-14624");

  script_name(english:"Debian DLA-1526-1 : 389-ds-base security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It was discovered that the emergency logging system in 389-ds-base
(the 389 Directory Server) is affected by a race condition caused by
the invalidation of the concurrently used log file file descriptor
without proper locking. This issue might be triggered by remote
attackers to cause DoS (crash) and any other undefined behavior.

For Debian 8 'Jessie', this problem has been fixed in version
1.3.3.5-4+deb8u3.

We recommend that you upgrade your 389-ds-base packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/09/msg00037.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/389-ds-base");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14624");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:389-ds-base-libs-dbg");
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
if (deb_check(release:"8.0", prefix:"389-ds", reference:"1.3.3.5-4+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base", reference:"1.3.3.5-4+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-dbg", reference:"1.3.3.5-4+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-dev", reference:"1.3.3.5-4+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-libs", reference:"1.3.3.5-4+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"389-ds-base-libs-dbg", reference:"1.3.3.5-4+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
