#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4785. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(142618);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id("CVE-2017-18926");
  script_xref(name:"DSA", value:"4785");

  script_name(english:"Debian DSA-4785-1 : raptor2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"It was discovered that raptor2, an RDF parser library, is prone to
heap-based buffer overflow flaws, which could result in denial of
service, or potentially the execution of arbitrary code, if a
specially crafted file is processed.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=973889");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/raptor2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/raptor2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4785");
  script_set_attribute(attribute:"solution", value:
"Upgrade the raptor2 packages.

For the stable distribution (buster), this problem has been fixed in
version 2.0.14-1.1~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18926");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:raptor2");
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
if (deb_check(release:"10.0", prefix:"libraptor2-0", reference:"2.0.14-1.1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libraptor2-0-dbg", reference:"2.0.14-1.1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libraptor2-dev", reference:"2.0.14-1.1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libraptor2-doc", reference:"2.0.14-1.1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"raptor2-utils", reference:"2.0.14-1.1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
