#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4282. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(112232);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/13");

  script_cve_id(
    "CVE-2018-1318",
    "CVE-2018-8004",
    "CVE-2018-8005",
    "CVE-2018-8040"
  );
  script_xref(name:"DSA", value:"4282");

  script_name(english:"Debian DSA-4282-1 : trafficserver - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were discovered in Apache Traffic Server, a
reverse and forward proxy server, which could result in denial of
service, cache poisoning or information disclosure.");
  # https://security-tracker.debian.org/tracker/source-package/trafficserver
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20613153");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/trafficserver");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2018/dsa-4282");
  script_set_attribute(attribute:"solution", value:
"Upgrade the trafficserver packages.

For the stable distribution (stretch), these problems have been fixed
in version 7.0.0-6+deb9u2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8040");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8004");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:trafficserver");
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
if (deb_check(release:"9.0", prefix:"trafficserver", reference:"7.0.0-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"trafficserver-dev", reference:"7.0.0-6+deb9u2")) flag++;
if (deb_check(release:"9.0", prefix:"trafficserver-experimental-plugins", reference:"7.0.0-6+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
