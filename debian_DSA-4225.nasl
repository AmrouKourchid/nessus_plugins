#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4225. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110424);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_cve_id(
    "CVE-2018-2790",
    "CVE-2018-2794",
    "CVE-2018-2795",
    "CVE-2018-2796",
    "CVE-2018-2797",
    "CVE-2018-2798",
    "CVE-2018-2799",
    "CVE-2018-2800",
    "CVE-2018-2814",
    "CVE-2018-2815"
  );
  script_xref(name:"DSA", value:"4225");

  script_name(english:"Debian DSA-4225-1 : openjdk-7 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in denial of
service, sandbox bypass, execution of arbitrary code or bypass of JAR
signature validation.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/openjdk-7");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/openjdk-7");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4225");
  script_set_attribute(attribute:"solution", value:
"Upgrade the openjdk-7 packages.

For the oldstable distribution (jessie), these problems have been
fixed in version 7u181-2.6.14-1~deb8u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2814");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
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
if (deb_check(release:"8.0", prefix:"icedtea-7-jre-jamvm", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-dbg", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-demo", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-doc", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jdk", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-headless", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-lib", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-jre-zero", reference:"7u181-2.6.14-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"openjdk-7-source", reference:"7u181-2.6.14-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
