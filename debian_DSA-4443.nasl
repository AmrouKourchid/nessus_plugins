#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4443. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(125094);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2018-16860");
  script_xref(name:"DSA", value:"4443");

  script_name(english:"Debian DSA-4443-1 : samba - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Isaac Boukris and Andrew Bartlett discovered that the S4U2Self
Kerberos extension used in Samba's Active Directory support was
susceptible to man-in-the-middle attacks caused by incomplete checksum
validation.

Details can be found in the upstream advisory at");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/samba");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/samba");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2019/dsa-4443");
  script_set_attribute(attribute:"solution", value:
"Upgrade the samba packages.

For the stable distribution (stretch), this problem has been fixed in
version 2:4.5.16+dfsg-1+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16860");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"9.0", prefix:"ctdb", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libnss-winbind", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libpam-winbind", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libparse-pidl-perl", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libsmbclient-dev", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient-dev", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libwbclient0", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"python-samba", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"registry-tools", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba-common-bin", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dev", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba-dsdb-modules", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba-libs", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba-testsuite", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"samba-vfs-modules", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"smbclient", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"winbind", reference:"2:4.5.16+dfsg-1+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
