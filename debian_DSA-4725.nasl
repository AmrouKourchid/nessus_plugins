#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4725. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138645);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/29");

  script_cve_id("CVE-2020-14928");
  script_xref(name:"DSA", value:"4725");

  script_name(english:"Debian DSA-4725-1 : evolution-data-server - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Damian Poddebniak and Fabian Ising discovered a response injection
vulnerability in Evolution data server, which could enable MITM
attacks.");
  # https://security-tracker.debian.org/tracker/source-package/evolution-data-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e2c5c27");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/evolution-data-server");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2020/dsa-4725");
  script_set_attribute(attribute:"solution", value:
"Upgrade the evolution-data-server packages.

For the stable distribution (buster), this problem has been fixed in
version 3.30.5-1+deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14928");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evolution-data-server");
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
if (deb_check(release:"10.0", prefix:"evolution-data-server", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"evolution-data-server-common", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"evolution-data-server-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"evolution-data-server-doc", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"evolution-data-server-tests", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-camel-1.2", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-ebook-1.2", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-ebookcontacts-1.2", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-edataserver-1.2", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"gir1.2-edataserverui-1.2", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcamel-1.2-62", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libcamel1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libebackend-1.2-10", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libebackend1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libebook-1.2-19", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libebook-contacts-1.2-2", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libebook-contacts1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libebook1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libecal-1.2-19", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libecal1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedata-book-1.2-25", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedata-book1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedata-cal-1.2-29", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedata-cal1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedataserver-1.2-23", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedataserver1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedataserverui-1.2-2", reference:"3.30.5-1+deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libedataserverui1.2-dev", reference:"3.30.5-1+deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
