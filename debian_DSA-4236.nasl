#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4236. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110787);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/12");

  script_cve_id("CVE-2018-12891", "CVE-2018-12892", "CVE-2018-12893");
  script_xref(name:"DSA", value:"4236");

  script_name(english:"Debian DSA-4236-1 : xen - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities have been discovered in the Xen hypervisor :

  - CVE-2018-12891
    It was discovered that insufficient validation of PV MMU
    operations may result in denial of service.

  - CVE-2018-12892
    It was discovered that libxl fails to honour the
    'readonly' flag on HVM-emulated SCSI disks.

  - CVE-2018-12893
    It was discovered that incorrect implementation of debug
    exception checks could result in denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-12891");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-12892");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-12893");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/xen");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/xen");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4236");
  script_set_attribute(attribute:"solution", value:
"Upgrade the xen packages.

For the stable distribution (stretch), these problems have been fixed
in version 4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12892");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (deb_check(release:"9.0", prefix:"libxen-4.8", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libxen-dev", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"libxenstore3.0", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-amd64", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-arm64", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-hypervisor-4.8-armhf", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-amd64", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-arm64", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-system-armhf", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-4.8", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xen-utils-common", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;
if (deb_check(release:"9.0", prefix:"xenstore-utils", reference:"4.8.3+xsa267+shim4.10.1+xsa267-1+deb9u9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
