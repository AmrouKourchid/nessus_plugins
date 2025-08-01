#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2556-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(146527);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/22");

  script_cve_id("CVE-2020-12662", "CVE-2020-12663", "CVE-2020-28935");

  script_name(english:"Debian DLA-2556-1 : unbound1.9 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several security vulnerabilities have been corrected in unbound, a
validating, recursive, caching DNS resolver. Support for the unbound
DNS server has been resumed, the sources can be found in the
unbound1.9 source package.

CVE-2020-12662

Unbound has Insufficient Control of Network Message Volume, aka an
'NXNSAttack' issue. This is triggered by random subdomains in the
NSDNAME in NS records.

CVE-2020-12663

Unbound has an infinite loop via malformed DNS answers received from
upstream servers.

CVE-2020-28935

Unbound contains a local vulnerability that would allow for a local
symlink attack. When writing the PID file Unbound creates the file if
it is not there, or opens an existing file for writing. In case the
file was already present, it would follow symlinks if the file
happened to be a symlink instead of a regular file. 

For Debian 9 stretch, these problems have been fixed in version
1.9.0-2+deb10u2~deb9u1.

We recommend that you upgrade your unbound1.9 packages.

For the detailed security status of unbound1.9 please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/unbound1.9

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2021/02/msg00017.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/unbound1.9");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/unbound1.9");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libunbound8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound-anchor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound-host");
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
if (deb_check(release:"9.0", prefix:"libunbound8", reference:"1.9.0-2+deb10u2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"unbound", reference:"1.9.0-2+deb10u2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"unbound-anchor", reference:"1.9.0-2+deb10u2~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"unbound-host", reference:"1.9.0-2+deb10u2~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
