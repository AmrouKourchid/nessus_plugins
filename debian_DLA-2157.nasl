#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2157-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134881);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/21");

  script_cve_id("CVE-2020-8955", "CVE-2020-9759", "CVE-2020-9760");

  script_name(english:"Debian DLA-2157-1 : weechat security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several issues have been found in weechat, a fast, light and
extensible chat client. All issues are about crafted messages, that
could result in a buffer overflow and application crash. This could
cause a denial of service or possibly have other impact.

For Debian 8 'Jessie', these problems have been fixed in version
1.0.1-1+deb8u3.

We recommend that you upgrade your weechat packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/03/msg00031.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/weechat");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-9759");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9760");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:weechat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:weechat-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:weechat-curses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:weechat-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:weechat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:weechat-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:weechat-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
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
if (deb_check(release:"8.0", prefix:"weechat", reference:"1.0.1-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"weechat-core", reference:"1.0.1-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"weechat-curses", reference:"1.0.1-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"weechat-dbg", reference:"1.0.1-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"weechat-dev", reference:"1.0.1-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"weechat-doc", reference:"1.0.1-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"weechat-plugins", reference:"1.0.1-1+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
