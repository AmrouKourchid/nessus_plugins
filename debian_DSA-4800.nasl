#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4800. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(143313);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/08");

  script_cve_id("CVE-2020-25219", "CVE-2020-26154");
  script_xref(name:"DSA", value:"4800");

  script_name(english:"Debian DSA-4800-1 : libproxy - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Two vulnerabilities were discovered in libproxy, an automatic proxy
configuration management library, which could result in denial of
service, or possibly, execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=968366");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=971394");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libproxy");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libproxy");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4800");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libproxy packages.

For the stable distribution (buster), these problems have been fixed
in version 0.4.15-5+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26154");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libproxy");
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
if (deb_check(release:"10.0", prefix:"libproxy-cil-dev", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy-dev", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy-tools", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy0.4-cil", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy1-plugin-gsettings", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy1-plugin-kconfig", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy1-plugin-mozjs", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy1-plugin-networkmanager", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy1-plugin-webkit", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libproxy1v5", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python-libproxy", reference:"0.4.15-5+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"python3-libproxy", reference:"0.4.15-5+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
