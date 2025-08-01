#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4541. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129596);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_cve_id("CVE-2019-12412");
  script_xref(name:"DSA", value:"4541");

  script_name(english:"Debian DSA-4541-1 : libapreq2 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"Max Kellermann reported a NULL pointer dereference flaw in libapreq2,
a generic Apache request library, allowing a remote attacker to cause
a denial of service against an application using the library
(application crash) if an invalid nested 'multipart' body is
processed.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=939937");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/libapreq2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/libapreq2");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/libapreq2");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2019/dsa-4541");
  script_set_attribute(attribute:"solution", value:
"Upgrade the libapreq2 packages.

For the oldstable distribution (stretch), this problem has been fixed
in version 2.13-7~deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 2.13-7~deb10u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libapreq2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (deb_check(release:"10.0", prefix:"libapache2-mod-apreq2", reference:"2.13-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libapache2-request-perl", reference:"2.13-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libapreq2-3", reference:"2.13-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libapreq2-dev", reference:"2.13-7~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"libapreq2-doc", reference:"2.13-7~deb10u1")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-mod-apreq2", reference:"2.13-7~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libapache2-request-perl", reference:"2.13-7~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libapreq2-3", reference:"2.13-7~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libapreq2-dev", reference:"2.13-7~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"libapreq2-doc", reference:"2.13-7~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
