#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2419-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142105);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id("CVE-2019-16728", "CVE-2020-26870");
  script_xref(name:"CEA-ID", value:"CEA-2021-0001");

  script_name(english:"Debian DLA-2419-1 : dompurify.js security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Two issues have been found in dompurify.js, an XSS sanitizer for HTML,
MathML and SVG.

Both issues are related to mXSS issues in SVG- or MATH-elements.

For Debian 9 stretch, these problems have been fixed in version
0.8.2~dfsg1-1+deb9u1.

We recommend that you upgrade your dompurify.js packages.

For the detailed security status of dompurify.js please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/dompurify.js

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00029.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/dompurify.js");
  # https://security-tracker.debian.org/tracker/source-package/dompurify.js
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?008b7ba5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected libjs-dompurify, and node-dompurify packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26870");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjs-dompurify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-dompurify");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (deb_check(release:"9.0", prefix:"libjs-dompurify", reference:"0.8.2~dfsg1-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"node-dompurify", reference:"0.8.2~dfsg1-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
