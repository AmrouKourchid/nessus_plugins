#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4290. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(117435);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/08");

  script_cve_id("CVE-2018-14346", "CVE-2018-14347", "CVE-2018-16430");
  script_xref(name:"DSA", value:"4290");

  script_name(english:"Debian DSA-4290-1 : libextractor - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were discovered in libextractor, a library to
extract arbitrary meta-data from files, which may lead to denial of
service or the execution of arbitrary code if a specially crafted file
is opened.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=904903");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=904905");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=907987");
  # https://security-tracker.debian.org/tracker/source-package/libextractor
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd14df80");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libextractor");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4290");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libextractor packages.

For the stable distribution (stretch), these problems have been fixed
in version 1:1.3-4+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16430");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libextractor");
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
if (deb_check(release:"9.0", prefix:"extract", reference:"1:1.3-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libextractor-dbg", reference:"1:1.3-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libextractor-dev", reference:"1:1.3-4+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"libextractor3", reference:"1:1.3-4+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
