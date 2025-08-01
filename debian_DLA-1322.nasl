#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1322-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108692);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/03");

  script_cve_id(
    "CVE-2017-18219",
    "CVE-2017-18220",
    "CVE-2017-18229",
    "CVE-2017-18230",
    "CVE-2017-18231",
    "CVE-2018-9018"
  );

  script_name(english:"Debian DLA-1322-1 : graphicsmagick security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Various security issues were discovered in Graphicsmagick, a
collection of image processing tools.

CVE-2017-18219 An allocation failure vulnerability was found in the
function ReadOnePNGImage in coders/png.c, which allows attackers to
cause a denial of service via a crafted file that triggers an attempt
at a large png_pixels array allocation.

CVE-2017-18220 The ReadOneJNGImage and ReadJNGImage functions in
coders/png.c allow remote attackers to cause a denial of service or
possibly have unspecified other impact via a crafted file, a related
issue to CVE-2017-11403.

CVE-2017-18229 An allocation failure vulnerability was found in the
function ReadTIFFImage in coders/tiff.c, which allows attackers to
cause a denial of service via a crafted file, because file size is not
properly used to restrict scanline, strip, and tile allocations.

CVE-2017-18230 A NULL pointer dereference vulnerability was found in
the function ReadCINEONImage in coders/cineon.c, which allows
attackers to cause a denial of service via a crafted file.

CVE-2017-18231 A NULL pointer dereference vulnerability was found in
the function ReadEnhMetaFile in coders/emf.c, which allows attackers
to cause a denial of service via a crafted file.

CVE-2018-9018 There is a divide-by-zero error in the ReadMNGImage
function of coders/png.c. Remote attackers could leverage this
vulnerability to cause a crash and denial of service via a crafted mng
file.

For Debian 7 'Wheezy', these problems have been fixed in version
1.3.16-1.1+deb7u19.

We recommend that you upgrade your graphicsmagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/03/msg00025.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/graphicsmagick");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18220");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-imagemagick-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-libmagick-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphics-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
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
if (deb_check(release:"7.0", prefix:"graphicsmagick", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-dbg", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphics-magick-perl", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick++3", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.16-1.1+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick3", reference:"1.3.16-1.1+deb7u19")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
