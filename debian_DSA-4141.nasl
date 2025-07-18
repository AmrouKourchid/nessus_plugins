#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4141. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108418);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/29");

  script_cve_id("CVE-2018-5147");
  script_xref(name:"DSA", value:"4141");

  script_name(english:"Debian DSA-4141-1 : libvorbisidec - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Huzaifa Sidhpurwala discovered that an out-of-bounds memory write in
the codebook parsing code of the Libtremor multimedia library could
result in the execution of arbitrary code if a malformed Vorbis file
is opened.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=893132");
  # https://security-tracker.debian.org/tracker/source-package/libvorbisidec
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a433cb89");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/libvorbisidec");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libvorbisidec");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4141");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libvorbisidec packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 1.0.2+svn18153-1~deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 1.0.2+svn18153-1+deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5147");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvorbisidec");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"8.0", prefix:"libvorbisidec-dev", reference:"1.0.2+svn18153-1~deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libvorbisidec1", reference:"1.0.2+svn18153-1~deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"libvorbisidec-dev", reference:"1.0.2+svn18153-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libvorbisidec1", reference:"1.0.2+svn18153-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
