#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2507-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(144681);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/31");

  script_cve_id("CVE-2020-26258", "CVE-2020-26259");

  script_name(english:"Debian DLA-2507-1 : libxstream-java security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several security vulnerabilities were discovered in XStream, a Java
library to serialize objects to XML and back again.

CVE-2020-26258

XStream is vulnerable to a Server-Side Forgery Request which can be
activated when unmarshalling. The vulnerability may allow a remote
attacker to request data from internal resources that are not publicly
available only by manipulating the processed input stream.

CVE-2020-26259

Xstream is vulnerable to an Arbitrary File Deletion on the local host
when unmarshalling. The vulnerability may allow a remote attacker to
delete arbitrary known files on the host as long as the executing
process has sufficient rights only by manipulating the processed input
stream.

For Debian 9 stretch, these problems have been fixed in version
1.4.11.1-1+deb9u1.

We recommend that you upgrade your libxstream-java packages.

For the detailed security status of libxstream-java please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/libxstream-java

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00042.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libxstream-java");
  # https://security-tracker.debian.org/tracker/source-package/libxstream-java
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2068716");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected libxstream-java package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26259");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-26258");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libxstream-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"9.0", prefix:"libxstream-java", reference:"1.4.11.1-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
