#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4170. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108906);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/12");

  script_cve_id(
    "CVE-2017-16872",
    "CVE-2017-16875",
    "CVE-2018-1000098",
    "CVE-2018-1000099"
  );
  script_xref(name:"DSA", value:"4170");

  script_name(english:"Debian DSA-4170-1 : pjproject - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities have been discovered in the PJSIP/PJProject
multimedia communication which may result in denial of service during
the processing of SIP and SDP messages and ioqueue keys.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/pjproject");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/pjproject");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4170");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pjproject packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.5.5~dfsg-6+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pjproject");
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
if (deb_check(release:"9.0", prefix:"libpj2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjlib-util2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjmedia-audiodev2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjmedia-codec2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjmedia-videodev2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjmedia2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjnath2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjproject-dev", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjsip-simple2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjsip-ua2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjsip2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjsua2", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libpjsua2-2v5", reference:"2.5.5~dfsg-6+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-pjproject", reference:"2.5.5~dfsg-6+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
