#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4544. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129985);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2019-16866");
  script_xref(name:"DSA", value:"4544");

  script_name(english:"Debian DSA-4544-1 : unbound - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"X41 D-Sec discovered that unbound, a validating, recursive, and
caching DNS resolver, did not correctly process some NOTIFY queries.
This could lead to remote denial-of-service by application crash.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=941692");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/unbound");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/unbound");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2019/dsa-4544");
  script_set_attribute(attribute:"solution", value:
"Upgrade the unbound packages.

For the stable distribution (buster), this problem has been fixed in
version 1.9.0-2+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16866");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:unbound");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (deb_check(release:"10.0", prefix:"libunbound-dev", reference:"1.9.0-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libunbound8", reference:"1.9.0-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python-unbound", reference:"1.9.0-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python3-unbound", reference:"1.9.0-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"unbound", reference:"1.9.0-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"unbound-anchor", reference:"1.9.0-2+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"unbound-host", reference:"1.9.0-2+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
