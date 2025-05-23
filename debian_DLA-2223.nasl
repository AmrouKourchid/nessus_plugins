#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2223-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136979);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/08");

  script_cve_id("CVE-2020-11651", "CVE-2020-11652");
  script_xref(name:"IAVA", value:"2020-A-0195-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"Debian DLA-2223-1 : salt security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Several vulnerabilities were discovered in package salt, a
configuration management and infrastructure automation software.

CVE-2020-11651

The salt-master process ClearFuncs class does not properly validate
method calls. This allows a remote user to access some methods without
authentication. These methods can be used to retrieve user tokens from
the salt master and/or run arbitrary commands on salt minions.

CVE-2020-11652

The salt-master process ClearFuncs class allows access to some methods
that improperly sanitize paths. These methods allow arbitrary
directory access to authenticated users.

For Debian 8 'Jessie', these problems have been fixed in version
2014.1.13+ds-3+deb8u1.

We recommend that you upgrade your salt packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2020/05/msg00027.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/salt");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (deb_check(release:"8.0", prefix:"salt-cloud", reference:"2014.1.13+ds-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"salt-common", reference:"2014.1.13+ds-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"salt-doc", reference:"2014.1.13+ds-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"salt-master", reference:"2014.1.13+ds-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"salt-minion", reference:"2014.1.13+ds-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"salt-ssh", reference:"2014.1.13+ds-3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"salt-syndic", reference:"2014.1.13+ds-3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
