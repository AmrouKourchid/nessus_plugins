#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4152. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108663);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/03");

  script_cve_id("CVE-2018-1000051", "CVE-2018-6544");
  script_xref(name:"DSA", value:"4152");

  script_name(english:"Debian DSA-4152-1 : mupdf - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Two vulnerabilities were discovered in MuPDF, a PDF, XPS, and e-book
viewer, which may result in denial of service or remote code
execution. An attacker can craft a PDF document which, when opened in
the victim host, might consume vast amounts of memory, crash the
program, or, in some cases, execute code in the context in which the
application is running.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=891245");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/mupdf");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/mupdf");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/mupdf");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4152");
  script_set_attribute(attribute:"solution", value:
"Upgrade the mupdf packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 1.5-1+deb8u4.

For the stable distribution (stretch), these problems have been fixed
in version 1.9a+ds1-4+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1000051");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mupdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
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
if (deb_check(release:"8.0", prefix:"libmupdf-dev", reference:"1.5-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"mupdf", reference:"1.5-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"mupdf-tools", reference:"1.5-1+deb8u4")) flag++;
if (deb_check(release:"9.0", prefix:"libmupdf-dev", reference:"1.9a+ds1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"mupdf", reference:"1.9a+ds1-4+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"mupdf-tools", reference:"1.9a+ds1-4+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
