#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1339-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(108815);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2641",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );

  script_name(english:"Debian DLA-1339-1 : openjdk-7 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in denial of
service, unauthorized access, sandbox bypass or HTTP header injection.

For Debian 7 'Wheezy', these problems have been fixed in version
7u171-2.6.13-1~deb7u1.

We recommend that you upgrade your openjdk-7 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/04/msg00003.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/openjdk-7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2637");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2633");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-7-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 Tenable Network Security, Inc.");

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
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-cacao", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-jamvm", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-dbg", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-demo", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-doc", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jdk", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-headless", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-lib", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-zero", reference:"7u171-2.6.13-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-source", reference:"7u171-2.6.13-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
