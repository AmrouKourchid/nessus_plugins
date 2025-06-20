#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4865. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(146922);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/18");

  script_cve_id(
    "CVE-2020-15157",
    "CVE-2020-15257",
    "CVE-2021-21284",
    "CVE-2021-21285"
  );
  script_xref(name:"DSA", value:"4865");

  script_name(english:"Debian DSA-4865-1 : docker.io - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Multiple security issues were discovered in Docker, a Linux container
runtime, which could result in denial of service, an information leak
or privilege escalation.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/docker.io");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/docker.io");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4865");
  script_set_attribute(attribute:"solution", value:
"Upgrade the docker.io packages.

For the stable distribution (buster), these problems have been fixed
in version 18.09.1+dfsg1-7.1+deb10u3.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15257");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-21284");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:docker.io");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (deb_check(release:"10.0", prefix:"docker-doc", reference:"18.09.1+dfsg1-7.1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"docker.io", reference:"18.09.1+dfsg1-7.1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"golang-docker-dev", reference:"18.09.1+dfsg1-7.1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"golang-github-docker-docker-dev", reference:"18.09.1+dfsg1-7.1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"vim-syntax-docker", reference:"18.09.1+dfsg1-7.1+deb10u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
