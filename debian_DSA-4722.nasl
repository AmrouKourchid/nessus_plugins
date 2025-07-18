#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4722. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138365);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/01");

  script_cve_id(
    "CVE-2019-13390",
    "CVE-2019-17539",
    "CVE-2019-17542",
    "CVE-2020-12284",
    "CVE-2020-13904"
  );
  script_xref(name:"DSA", value:"4722");

  script_name(english:"Debian DSA-4722-1 : ffmpeg - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities have been discovered in the FFmpeg multimedia
framework, which could result in denial of service or potentially the
execution of arbitrary code if malformed files/streams are processed.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ffmpeg");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ffmpeg");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4722");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ffmpeg packages.

For the stable distribution (buster), these problems have been fixed
in version 7:4.1.6-1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-12284");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"10.0", prefix:"ffmpeg", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ffmpeg-doc", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavcodec-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavcodec-extra", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavcodec-extra58", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavcodec58", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavdevice-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavdevice58", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavfilter-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavfilter-extra", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavfilter-extra7", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavfilter7", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavformat-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavformat58", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavresample-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavresample4", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavutil-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libavutil56", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpostproc-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libpostproc55", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libswresample-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libswresample3", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libswscale-dev", reference:"7:4.1.6-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libswscale5", reference:"7:4.1.6-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
