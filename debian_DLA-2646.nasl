#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2646-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149246);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2020-17525");

  script_name(english:"Debian DLA-2646-1 : subversion security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"One security issue has been discovered in subversion :

CVE-2020-17525 :

Subversion's mod_authz_svn module will crash if the server is using
in-repository authz rules with the AuthzSVNReposRelativeAccessFile
option and a client sends a request for a non-existing repository URL.
This can lead to disruption for users of the service.

For Debian 9 stretch, this problem has been fixed in version
1.9.5-1+deb9u6.

We recommend that you upgrade your subversion packages.

For the detailed security status of subversion please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/subversion

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/subversion"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17525");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapache2-mod-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsvn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

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
if (deb_check(release:"9.0", prefix:"libapache2-mod-svn", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-dev", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-doc", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-java", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn-perl", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"libsvn1", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"python-subversion", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"ruby-svn", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"subversion", reference:"1.9.5-1+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"subversion-tools", reference:"1.9.5-1+deb9u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
