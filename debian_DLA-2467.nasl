#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2467-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143308);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id("CVE-2020-27783");

  script_name(english:"Debian DLA-2467-2 : lxml regression update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The fix for CVE-2020-27783, released as DLA 2467-1, was incomplete as
the <math/svg> component was still affected by the vulnerability. This
update includes an additional patch that completes the fix. Note that
a package with version 3.7.1-1+deb9u2 was uploaded, but before the
publication of the advisory a regression was discovered, which was
immediately corrected prior to publication of this advisory.

For Debian 9 stretch, this problem has been fixed in version
3.7.1-1+deb9u3.

We recommend that you upgrade your lxml packages.

For the detailed security status of lxml please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/lxml

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00028.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/lxml");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/lxml");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27783");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-lxml-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-lxml-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-lxml-dbg");
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
if (deb_check(release:"9.0", prefix:"python-lxml", reference:"3.7.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-lxml-dbg", reference:"3.7.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python-lxml-doc", reference:"3.7.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python3-lxml", reference:"3.7.1-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"python3-lxml-dbg", reference:"3.7.1-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
