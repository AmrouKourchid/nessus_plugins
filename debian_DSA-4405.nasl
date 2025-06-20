#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4405. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(122724);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/14");

  script_cve_id(
    "CVE-2017-17480",
    "CVE-2018-14423",
    "CVE-2018-18088",
    "CVE-2018-5785",
    "CVE-2018-6616"
  );
  script_xref(name:"DSA", value:"4405");

  script_name(english:"Debian DSA-4405-1 : openjpeg2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities have been discovered in openjpeg2, the
open-source JPEG 2000 codec, that could be leveraged to cause a denial
of service or possibly remote code execution.

  - CVE-2017-17480
    Write stack-based buffer overflow in the jp3d and jpwl
    codecs can result in a denial of service or remote code
    execution via a crafted jp3d or jpwl file.

  - CVE-2018-5785
    Integer overflow can result in a denial of service via a
    crafted bmp file.

  - CVE-2018-6616
    Excessive iteration can result in a denial of service
    via a crafted bmp file.

  - CVE-2018-14423
    Division-by-zero vulnerabilities can result in a denial
    of service via a crafted j2k file.

  - CVE-2018-18088
    NULL pointer dereference can result in a denial of
    service via a crafted bmp file.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=884738");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=888533");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=889683");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=904873");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=910763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2017-17480");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-5785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-6616");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-14423");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2018-18088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openjpeg2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/openjpeg2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2019/dsa-4405");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openjpeg2 packages.

For the stable distribution (stretch), these problems have been fixed
in version 2.1.2-1.1+deb9u3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17480");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjpeg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (deb_check(release:"9.0", prefix:"libopenjp2-7", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp2-7-dbg", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp2-7-dev", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp2-tools", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp3d-tools", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjp3d7", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip-dec-server", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip-server", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip-viewer", reference:"2.1.2-1.1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libopenjpip7", reference:"2.1.2-1.1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
