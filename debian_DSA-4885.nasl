#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4885. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(148326);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/12");

  script_cve_id("CVE-2019-20444", "CVE-2019-20445", "CVE-2020-11612", "CVE-2020-7238", "CVE-2021-21290", "CVE-2021-21295", "CVE-2021-21409");
  script_xref(name:"DSA", value:"4885");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Debian DSA-4885-1 : netty - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Multiple security issues were discovered in Netty, a Java NIO
client/server framework, which could result in HTTP request smuggling,
denial of service or information disclosure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/netty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/netty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2021/dsa-4885"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade the netty packages.

For the stable distribution (buster), these problems have been fixed
in version 1:4.1.33-1+deb10u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-20445");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:netty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/06");
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
if (deb_check(release:"10.0", prefix:"libnetty-java", reference:"1:4.1.33-1+deb10u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
