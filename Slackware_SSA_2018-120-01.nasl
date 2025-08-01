#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2018-120-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109432);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/16");

  script_cve_id(
    "CVE-2004-0941",
    "CVE-2006-3376",
    "CVE-2007-0455",
    "CVE-2007-2756",
    "CVE-2007-3472",
    "CVE-2007-3473",
    "CVE-2007-3477",
    "CVE-2009-3546",
    "CVE-2015-0848",
    "CVE-2015-4588",
    "CVE-2015-4695",
    "CVE-2015-4696",
    "CVE-2016-10167",
    "CVE-2016-10168",
    "CVE-2016-9011",
    "CVE-2016-9317",
    "CVE-2017-6362"
  );
  script_xref(name:"SSA", value:"2018-120-01");

  script_name(english:"Slackware 13.0 / 13.1 / 13.37 / 14.0 / 14.1 / 14.2 / current : libwmf (SSA:2018-120-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"New libwmf packages are available for Slackware 13.0, 13.1, 13.37,
14.0, 14.1, 14.2, and -current to fix security issues.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2018&m=slackware-security.620340
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0268bf61");
  script_set_attribute(attribute:"solution", value:
"Update the affected libwmf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-0941");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-10168");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:libwmf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:13.37");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (slackware_check(osver:"13.0", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"i486", pkgnum:"5_slack13.0")) flag++;
if (slackware_check(osver:"13.0", arch:"x86_64", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"x86_64", pkgnum:"5_slack13.0")) flag++;

if (slackware_check(osver:"13.1", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"i486", pkgnum:"6_slack13.1")) flag++;
if (slackware_check(osver:"13.1", arch:"x86_64", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"x86_64", pkgnum:"6_slack13.1")) flag++;

if (slackware_check(osver:"13.37", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"i486", pkgnum:"6_slack13.37")) flag++;
if (slackware_check(osver:"13.37", arch:"x86_64", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"x86_64", pkgnum:"6_slack13.37")) flag++;

if (slackware_check(osver:"14.0", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"i486", pkgnum:"6_slack14.0")) flag++;
if (slackware_check(osver:"14.0", arch:"x86_64", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"x86_64", pkgnum:"6_slack14.0")) flag++;

if (slackware_check(osver:"14.1", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"i486", pkgnum:"6_slack14.1")) flag++;
if (slackware_check(osver:"14.1", arch:"x86_64", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"x86_64", pkgnum:"6_slack14.1")) flag++;

if (slackware_check(osver:"14.2", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"i586", pkgnum:"7_slack14.1")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"x86_64", pkgnum:"7_slack14.1")) flag++;

if (slackware_check(osver:"current", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"i586", pkgnum:"8")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"libwmf", pkgver:"0.2.8.4", pkgarch:"x86_64", pkgnum:"8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:slackware_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
