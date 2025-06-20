#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2305-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139248);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/27");

  script_cve_id("CVE-2018-10756");

  script_name(english:"Debian DLA-2305-1 : transmission security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Use-after-free in libtransmission/variant.c in Transmission before
3.00 allows remote attackers to cause a denial of service (crash) or
possibly execute arbitrary code via a crafted torrent file.

For Debian 9 stretch, this problem has been fixed in version
2.92-2+deb9u2.

We recommend that you upgrade your transmission packages.

For the detailed security status of transmission please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/transmission

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/transmission");
  # https://security-tracker.debian.org/tracker/source-package/transmission
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1861ed77");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10756");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:transmission-qt");
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
if (deb_check(release:"9.0", prefix:"transmission", reference:"2.92-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"transmission-cli", reference:"2.92-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"transmission-common", reference:"2.92-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"transmission-daemon", reference:"2.92-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"transmission-gtk", reference:"2.92-2+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"transmission-qt", reference:"2.92-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
