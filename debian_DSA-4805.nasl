#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4805. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143551);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id("CVE-2020-17508", "CVE-2020-17509");
  script_xref(name:"DSA", value:"4805");

  script_name(english:"Debian DSA-4805-1 : trafficserver - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Two vulnerabilities were discovered in Apache Traffic Server, a
reverse and forward proxy server :

  - CVE-2020-17508
    The ESI plugin was vulnerable to memory disclosure.

  - CVE-2020-17509
    The negative cache option was vulnerable to cache
    poisoning.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-17508");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-17509");
  # https://security-tracker.debian.org/tracker/source-package/trafficserver
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20613153");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/trafficserver");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4805");
  script_set_attribute(attribute:"solution", value:
"Upgrade the trafficserver packages.

For the stable distribution (buster), these problems have been fixed
in version 8.0.2+ds-1+deb10u4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17508");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-17509");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
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
if (deb_check(release:"10.0", prefix:"trafficserver", reference:"8.0.2+ds-1+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"trafficserver-dev", reference:"8.0.2+ds-1+deb10u4")) flag++;
if (deb_check(release:"10.0", prefix:"trafficserver-experimental-plugins", reference:"8.0.2+ds-1+deb10u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
