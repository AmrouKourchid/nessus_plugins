#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4632. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133880);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/26");

  script_cve_id("CVE-2020-8597");
  script_xref(name:"DSA", value:"4632");
  script_xref(name:"CEA-ID", value:"CEA-2020-0025");

  script_name(english:"Debian DSA-4632-1 : ppp - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Ilja Van Sprundel reported a logic flaw in the Extensible
Authentication Protocol (EAP) packet parser in the Point-to-Point
Protocol Daemon (pppd). An unauthenticated attacker can take advantage
of this flaw to trigger a stack-based buffer overflow, leading to
denial of service (pppd daemon crash).");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=950618");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ppp");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/ppp");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/ppp");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4632");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ppp packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 2.4.7-1+4+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 2.4.7-2+4.1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8597");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ppp");
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
if (deb_check(release:"10.0", prefix:"ppp", reference:"2.4.7-2+4.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-dev", reference:"2.4.7-2+4.1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"ppp-udeb", reference:"2.4.7-2+4.1+deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"ppp", reference:"2.4.7-1+4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ppp-dev", reference:"2.4.7-1+4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"ppp-udeb", reference:"2.4.7-1+4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
