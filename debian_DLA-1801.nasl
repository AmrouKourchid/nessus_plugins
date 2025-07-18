#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1801-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125407);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/21");

  script_cve_id("CVE-2019-0201");

  script_name(english:"Debian DLA-1801-1 : zookeeper security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"It was discovered that there was an information disclosure
vulnerability in zookeeper, a distributed co-ordination server. Users
who were not authorised to read data were able to view the access
control list.

For Debian 8 'Jessie', this issue has been fixed in zookeeper version
3.4.9-3+deb8u2.

We recommend that you upgrade your zookeeper packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00033.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/zookeeper");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0201");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzookeeper-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzookeeper-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzookeeper-mt-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzookeeper-mt2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzookeeper-st-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzookeeper-st2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libzookeeper2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-zookeeper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zookeeper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zookeeper-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zookeeperd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
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
if (deb_check(release:"8.0", prefix:"libzookeeper-java", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libzookeeper-java-doc", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libzookeeper-mt-dev", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libzookeeper-mt2", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libzookeeper-st-dev", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libzookeeper-st2", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libzookeeper2", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"python-zookeeper", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zookeeper", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zookeeper-bin", reference:"3.4.9-3+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"zookeeperd", reference:"3.4.9-3+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
