#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4222. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(110421);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/24");

  script_cve_id("CVE-2018-12020");
  script_xref(name:"DSA", value:"4222");

  script_name(english:"Debian DSA-4222-1 : gnupg2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Marcus Brinkmann discovered that GnuPG performed insufficient
sanitisation of file names displayed in status messages, which could
be abused to fake the verification status of a signed email.

Details can be found in the upstream advisory at
https://lists.gnupg.org/pipermail/gnupg-announce/2018q2/000425.html");
  script_set_attribute(attribute:"see_also", value:"https://lists.gnupg.org/pipermail/gnupg-announce/2018q2/000425.html");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/gnupg2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/gnupg2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/gnupg2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4222");
  script_set_attribute(attribute:"solution", value:
"Upgrade the gnupg2 packages.

For the oldstable distribution (jessie), this problem has been fixed
in version 2.0.26-6+deb8u2.

For the stable distribution (stretch), this problem has been fixed in
version 2.1.18-8~deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12020");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (deb_check(release:"8.0", prefix:"gnupg-agent", reference:"2.0.26-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gnupg2", reference:"2.0.26-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gpgsm", reference:"2.0.26-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"gpgv2", reference:"2.0.26-6+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"scdaemon", reference:"2.0.26-6+deb8u2")) flag++;
if (deb_check(release:"9.0", prefix:"dirmngr", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gnupg", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gnupg-agent", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gnupg-l10n", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gnupg2", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gpgsm", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gpgv", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gpgv-static", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gpgv-udeb", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gpgv-win32", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"gpgv2", reference:"2.1.18-8~deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"scdaemon", reference:"2.1.18-8~deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
