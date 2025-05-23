#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4873. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(148172);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/12");

  script_cve_id("CVE-2020-25097");
  script_xref(name:"DSA", value:"4873");
  script_xref(name:"IAVB", value:"2021-B-0021-S");

  script_name(english:"Debian DSA-4873-1 : squid - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Jianjun Chen discovered that the Squid proxy caching server was
susceptible to HTTP request smuggling.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=985068");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/squid");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/squid");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2021/dsa-4873");
  script_set_attribute(attribute:"solution", value:
"Upgrade the squid packages.

For the stable distribution (buster), this problem has been fixed in
version 4.6-1+deb10u5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25097");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:squid");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"10.0", prefix:"squid", reference:"4.6-1+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"squid-cgi", reference:"4.6-1+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"squid-common", reference:"4.6-1+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"squid-purge", reference:"4.6-1+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"squid3", reference:"4.6-1+deb10u5")) flag++;
if (deb_check(release:"10.0", prefix:"squidclient", reference:"4.6-1+deb10u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
