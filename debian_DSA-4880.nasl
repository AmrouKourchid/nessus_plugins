#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4880. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148234);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2021-28957");
  script_xref(name:"DSA", value:"4880");

  script_name(english:"Debian DSA-4880-1 : lxml - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Kevin Chung discovered that lxml, a Python binding for the libxml2 and
libxslt libraries, did not properly sanitize its input. This would
allow a malicious user to mount a cross-site scripting attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=985643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/lxml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/lxml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4880"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the lxml packages.

For the stable distribution (buster), this problem has been fixed in
version 4.3.2-1+deb10u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28957");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lxml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

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
if (deb_check(release:"10.0", prefix:"python-lxml", reference:"4.3.2-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"python-lxml-dbg", reference:"4.3.2-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"python-lxml-doc", reference:"4.3.2-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"python3-lxml", reference:"4.3.2-1+deb10u3")) flag++;
if (deb_check(release:"10.0", prefix:"python3-lxml-dbg", reference:"4.3.2-1+deb10u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
