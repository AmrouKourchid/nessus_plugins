#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4677. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136373);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/13");

  script_cve_id(
    "CVE-2019-16217",
    "CVE-2019-16218",
    "CVE-2019-16219",
    "CVE-2019-16220",
    "CVE-2019-16221",
    "CVE-2019-16222",
    "CVE-2019-16223",
    "CVE-2019-16780",
    "CVE-2019-16781",
    "CVE-2019-17669",
    "CVE-2019-17671",
    "CVE-2019-17672",
    "CVE-2019-17673",
    "CVE-2019-17674",
    "CVE-2019-17675",
    "CVE-2019-20041",
    "CVE-2019-20042",
    "CVE-2019-20043",
    "CVE-2019-9787",
    "CVE-2020-11025",
    "CVE-2020-11026",
    "CVE-2020-11027",
    "CVE-2020-11028",
    "CVE-2020-11029",
    "CVE-2020-11030"
  );
  script_xref(name:"DSA", value:"4677");
  script_xref(name:"IAVA", value:"2020-A-0191-S");

  script_name(english:"Debian DSA-4677-1 : wordpress - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were discovered in Wordpress, a web blogging
tool. They allowed remote attackers to perform various Cross-Side
Scripting (XSS) and Cross-Site Request Forgery (CSRF) attacks, create
files on the server, disclose private information, create open
redirects, poison cache, and bypass authorization access and input
sanitation.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=924546");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=939543");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=942459");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=946905");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=959391");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/wordpress");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4677");
  script_set_attribute(attribute:"solution", value:
"Upgrade the wordpress packages.

For the oldstable distribution (stretch), these problems have been
fixed in version 4.7.5+dfsg-2+deb9u6.

For the stable distribution (buster), these problems have been fixed
in version 5.0.4+dfsg1-1+deb10u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20041");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (deb_check(release:"10.0", prefix:"wordpress", reference:"5.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-l10n", reference:"5.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-theme-twentynineteen", reference:"5.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-theme-twentyseventeen", reference:"5.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"10.0", prefix:"wordpress-theme-twentysixteen", reference:"5.0.4+dfsg1-1+deb10u2")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress", reference:"4.7.5+dfsg-2+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-l10n", reference:"4.7.5+dfsg-2+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyfifteen", reference:"4.7.5+dfsg-2+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentyseventeen", reference:"4.7.5+dfsg-2+deb9u6")) flag++;
if (deb_check(release:"9.0", prefix:"wordpress-theme-twentysixteen", reference:"4.7.5+dfsg-2+deb9u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
