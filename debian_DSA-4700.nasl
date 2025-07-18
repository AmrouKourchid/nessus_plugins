#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4700. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137373);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/26");

  script_cve_id("CVE-2020-13964", "CVE-2020-13965");
  script_xref(name:"DSA", value:"4700");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/17");

  script_name(english:"Debian DSA-4700-1 : roundcube - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Matei Badanoiu and LoRexxar@knownsec discovered that roundcube, a
skinnable AJAX based webmail solution for IMAP servers, did not
correctly process and sanitize requests. This would allow a remote
attacker to perform a Cross-Side Scripting (XSS) attack leading to the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=962123");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=962124");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/roundcube");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/roundcube");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/roundcube");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4700");
  script_set_attribute(attribute:"solution", value:
"Upgrade the roundcube packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 1.2.3+dfsg.1-4+deb9u5.

For the stable distribution (buster), these problems have been fixed
in version 1.3.13+dfsg.1-1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13965");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:roundcube");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (deb_check(release:"10.0", prefix:"roundcube", reference:"1.3.13+dfsg.1-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"roundcube-core", reference:"1.3.13+dfsg.1-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"roundcube-mysql", reference:"1.3.13+dfsg.1-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"roundcube-pgsql", reference:"1.3.13+dfsg.1-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"roundcube-plugins", reference:"1.3.13+dfsg.1-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"roundcube-sqlite3", reference:"1.3.13+dfsg.1-1~deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube", reference:"1.2.3+dfsg.1-4+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-core", reference:"1.2.3+dfsg.1-4+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-mysql", reference:"1.2.3+dfsg.1-4+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-pgsql", reference:"1.2.3+dfsg.1-4+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-plugins", reference:"1.2.3+dfsg.1-4+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"roundcube-sqlite3", reference:"1.2.3+dfsg.1-4+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
