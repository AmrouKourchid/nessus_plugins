#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1166-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104440);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_name(english:"Debian DLA-1166-2 : tomcat7 regression update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The update for tomcat7 issued as DLA-1166-1 caused a regressions
whereby every request, including for the root document (/), returned
HTTP status 404. Updated packages are now available to address this
problem. For reference, the original advisory text follows.

When HTTP PUT was enabled (e.g., via setting the readonly
initialization parameter of the Default servlet to false) it was
possible to upload a JSP file to the server via a specially crafted
request. This JSP could then be requested and any code it contained
would be executed by the server.

For Debian 7 'Wheezy', these problems have been fixed in version
7.0.28-4+deb7u17.

We recommend that you upgrade your tomcat7 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2017/11/msg00012.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/tomcat7");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.0-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet3.0-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat7-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat7-user");
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
if (deb_check(release:"7.0", prefix:"libservlet3.0-java", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"libservlet3.0-java-doc", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"libtomcat7-java", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-admin", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-common", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-docs", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-examples", reference:"7.0.28-4+deb7u17")) flag++;
if (deb_check(release:"7.0", prefix:"tomcat7-user", reference:"7.0.28-4+deb7u17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
