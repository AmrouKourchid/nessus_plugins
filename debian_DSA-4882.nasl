#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4882. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148305);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2020-15389", "CVE-2020-27814", "CVE-2020-27823", "CVE-2020-27824", "CVE-2020-27841", "CVE-2020-27842", "CVE-2020-27843", "CVE-2020-27845", "CVE-2020-6851", "CVE-2020-8112");
  script_xref(name:"DSA", value:"4882");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DSA-4882-1 : openjpeg2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple vulnerabilities have been discovered in openjpeg2, the
open-source JPEG 2000 codec, which could result in denial of service
or the execution of arbitrary code when opening a malformed image."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openjpeg2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/openjpeg2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4882"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the openjpeg2 packages.

For the stable distribution (buster), these problems have been fixed
in version 2.3.0-2+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8112");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

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
if (deb_check(release:"10.0", prefix:"libopenjp2-7", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjp2-7-dev", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjp2-tools", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjp3d-tools", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjp3d7", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjpip-dec-server", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjpip-server", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjpip-viewer", reference:"2.3.0-2+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"libopenjpip7", reference:"2.3.0-2+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
