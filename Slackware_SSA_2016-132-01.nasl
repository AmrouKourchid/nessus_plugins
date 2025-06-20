#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2016-132-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(91046);
  script_version("2.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2016-3714",
    "CVE-2016-3715",
    "CVE-2016-3716",
    "CVE-2016-3717",
    "CVE-2016-3718"
  );
  script_xref(name:"SSA", value:"2016-132-01");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/30");

  script_name(english:"Slackware 14.0 / 14.1 / current : mozilla-thunderbird (SSA:2016-132-01) (ImageTragick)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"New mozilla-thunderbird packages are available for Slackware 14.1 and
-current to fix security issues.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.359500
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a01f0c3");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.440568
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27bd7c00");
  script_set_attribute(attribute:"solution", value:
"Update the affected imagemagick and / or mozilla-thunderbird packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3714");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"14.0", pkgname:"imagemagick", pkgver:"6.7.7_10", pkgarch:"i486", pkgnum:"2_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"imagemagick", pkgver:"6.7.7_10", pkgarch:"x86_64", pkgnum:"2_slack14.0")) flag++;

if (slackware_check(osver:"14.1", pkgname:"imagemagick", pkgver:"6.8.6_10", pkgarch:"i486", pkgnum:"2_slack14.1")) flag++;
if (slackware_check(osver:"14.1", pkgname:"mozilla-thunderbird", pkgver:"45.1.0", pkgarch:"i486", pkgnum:"1_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"imagemagick", pkgver:"6.8.6_10", pkgarch:"x86_64", pkgnum:"2_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"mozilla-thunderbird", pkgver:"45.1.0", pkgarch:"x86_64", pkgnum:"1_slack14.1")) flag++;

if (slackware_check(osver:"current", pkgname:"imagemagick", pkgver:"6.9.4_1", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"mozilla-thunderbird", pkgver:"45.1.0", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"imagemagick", pkgver:"6.9.4_1", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"mozilla-thunderbird", pkgver:"45.1.0", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
