#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3713. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94901);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");
  script_xref(name:"DSA", value:"3713");

  script_name(english:"Debian DSA-3713-1 : gst-plugins-bad0.10 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Chris Evans discovered that the GStreamer 0.10 plugin to decode NES
Sound Format files allowed the execution of arbitrary code. Further
details can be found in his advisory at
http://scarybeastsecurity.blogspot.de/2016/11/0day-exploit-compromisin
g-linux-desktop.html.");
  # http://scarybeastsecurity.blogspot.de/2016/11/0day-exploit-compromising-linux-desktop.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fea1c5e7");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/gst-plugins-bad0.10");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2016/dsa-3713");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gst-plugins-bad0.10 packages.

For the stable distribution (jessie), this problem has been fixed in
version 0.10.23-7.4+deb8u1.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-bad0.10");
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
if (deb_check(release:"8.0", prefix:"gstreamer0.10-plugins-bad", reference:"0.10.23-7.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"gstreamer0.10-plugins-bad-dbg", reference:"0.10.23-7.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad0.10-0", reference:"0.10.23-7.4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgstreamer-plugins-bad0.10-dev", reference:"0.10.23-7.4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
