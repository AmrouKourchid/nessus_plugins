#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3675. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93693);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_xref(name:"DSA", value:"3675");

  script_name(english:"Debian DSA-3675-1 : imagemagick - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"This updates fixes several vulnerabilities in imagemagick: Various
memory handling problems and cases of missing or incomplete input
sanitising may result in denial of service or the execution of
arbitrary code if malformed SIXEL, PDB, MAP, SGI, TIFF and CALS files
are processed.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=836776");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=836172");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=836171");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/imagemagick");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2016/dsa-3675");
  script_set_attribute(attribute:"solution", value:
"Upgrade the imagemagick packages.

For the stable distribution (jessie), these problems have been fixed
in version 8:6.8.9.9-5+deb8u5.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"imagemagick", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-6.q16", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-common", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-dbg", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"imagemagick-doc", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-perl", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libimage-magick-q16-perl", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6-headers", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-5", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-6.q16-dev", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagick++-dev", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-arch-config", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6-headers", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-2-extra", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-6.q16-dev", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickcore-dev", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6-headers", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-2", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-6.q16-dev", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libmagickwand-dev", reference:"8:6.8.9.9-5+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"perlmagick", reference:"8:6.8.9.9-5+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
