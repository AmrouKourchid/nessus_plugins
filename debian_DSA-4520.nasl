#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4520. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128621);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id(
    "CVE-2019-9512",
    "CVE-2019-9514",
    "CVE-2019-9515",
    "CVE-2019-9518"
  );
  script_xref(name:"DSA", value:"4520");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Debian DSA-4520-1 : trafficserver - security update (Empty Frames Flood) (Ping Flood) (Reset Flood) (Settings Flood)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were discovered in the HTTP/2 code of Apache
Traffic Server, a reverse and forward proxy server, which could result
in denial of service.

The fixes are too intrusive to backport to the version in the
oldstable distribution (stretch). An upgrade to Debian stable (buster)
is recommended instead.");
  # https://security-tracker.debian.org/tracker/source-package/trafficserver
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20613153");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/trafficserver");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2019/dsa-4520");
  script_set_attribute(attribute:"solution", value:
"Upgrade the trafficserver packages.

For the stable distribution (buster), these problems have been fixed
in version 8.0.2+ds-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"10.0", prefix:"trafficserver", reference:"8.0.2+ds-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"trafficserver-dev", reference:"8.0.2+ds-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"trafficserver-experimental-plugins", reference:"8.0.2+ds-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
