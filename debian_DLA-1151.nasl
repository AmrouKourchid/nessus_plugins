#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1151-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104300);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/02");

  script_name(english:"Debian DLA-1151-2 : wordpress regression update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The fix for CVE-2017-14990 issued as DLA-1151-1 was incomplete and
caused a regression. It was discovered that an additional database
upgrade and further code changes would be necessary. At the moment
these changes are deemed as too intrusive and thus the initial patch
for CVE-2017-14990 has been removed again. For reference, the original
advisory text follows.

WordPress stores cleartext wp_signups.activation_key values (but
stores the analogous wp_users.user_activation_key values as hashes),
which might make it easier for remote attackers to hijack unactivated
user accounts by leveraging database read access (such as access
gained through an unspecified SQL injection vulnerability).

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.1+dfsg-1~deb7u19.

We recommend that you upgrade your wordpress packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2017/11/msg00015.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/wheezy/wordpress");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected wordpress, and wordpress-l10n packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress-l10n");
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
if (deb_check(release:"7.0", prefix:"wordpress", reference:"3.6.1+dfsg-1~deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"wordpress-l10n", reference:"3.6.1+dfsg-1~deb7u19")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
