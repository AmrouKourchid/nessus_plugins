#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-836-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(97394);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_name(english:"Debian DLA-836-2 : munin regression update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The update for munin issued as DLA-836-1 caused a regression in the
zooming functionality in munin-cgi-graph. Updated packages are now
available to correct this issue. For reference, the original advisory
text follows.

Stevie Trujillo discovered a command injection vulnerability in munin,
a network-wide graphing framework. The CGI script for drawing graphs
allowed to pass arbitrary GET parameters to local shell command,
allowing command execution as the user that runs the webserver.

For Debian 7 'Wheezy', these problems have been fixed in version
2.0.6-4+deb7u4.

We recommend that you upgrade your munin packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/munin");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-async");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-plugins-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-plugins-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 Tenable Network Security, Inc.");

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
if (deb_check(release:"7.0", prefix:"munin", reference:"2.0.6-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"munin-async", reference:"2.0.6-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"munin-common", reference:"2.0.6-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"munin-doc", reference:"2.0.6-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"munin-node", reference:"2.0.6-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"munin-plugins-core", reference:"2.0.6-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"munin-plugins-extra", reference:"2.0.6-4+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"munin-plugins-java", reference:"2.0.6-4+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
