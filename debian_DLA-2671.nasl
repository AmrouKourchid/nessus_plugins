#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2671-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(150099);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2021-33477");

  script_name(english:"Debian DLA-2671-1 : rxvt-unicode security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"rxvt-unicode allow (potentially remote) code execution because of
improper handling of certain escape sequences (ESC G Q). A response is
terminated by a newline.

For Debian 9 stretch, this problem has been fixed in version
9.22-1+deb9u1.

We recommend that you upgrade your rxvt-unicode packages.

For the detailed security status of rxvt-unicode please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/rxvt-unicode

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/05/msg00026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/rxvt-unicode"
  );
  # https://security-tracker.debian.org/tracker/source-package/rxvt-unicode
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dd2cc31"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-33477");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rxvt-unicode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rxvt-unicode-256color");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rxvt-unicode-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rxvt-unicode-ml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/01");
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
if (deb_check(release:"9.0", prefix:"rxvt-unicode", reference:"9.22-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"rxvt-unicode-256color", reference:"9.22-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"rxvt-unicode-lite", reference:"9.22-1+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"rxvt-unicode-ml", reference:"9.22-1+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
