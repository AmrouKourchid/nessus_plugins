#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1480-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112167);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/14");

  script_cve_id("CVE-2016-2337", "CVE-2018-1000073", "CVE-2018-1000074");

  script_name(english:"Debian DLA-1480-1 : ruby2.1 security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were discovered in Ruby 2.1.

CVE-2016-2337

Type confusion exists in _cancel_eval Ruby's TclTkIp class method.
Attacker passing different type of object than String as 'retval'
argument can cause arbitrary code execution.

CVE-2018-1000073

RubyGems contains a Directory Traversal vulnerability in
install_location function of package.rb that can result in path
traversal when writing to a symlinked basedir outside of the root.

CVE-2018-1000074

RubyGems contains a Deserialization of Untrusted Data vulnerability in
owner command that can result in code execution. This attack appear to
be exploitable via victim must run the `gem owner` command on a gem
with a specially crafted YAML file.

For Debian 8 'Jessie', these problems have been fixed in version
2.1.5-2+deb8u5.

We recommend that you upgrade your ruby2.1 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2018/08/msg00028.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/ruby2.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2337");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby2.1-tcltk");
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
if (deb_check(release:"8.0", prefix:"libruby2.1", reference:"2.1.5-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1", reference:"2.1.5-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1-dev", reference:"2.1.5-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1-doc", reference:"2.1.5-2+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"ruby2.1-tcltk", reference:"2.1.5-2+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
