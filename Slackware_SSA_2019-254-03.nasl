#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2019-254-03. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('compat.inc');

if (description)
{
  script_id(128751);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id("CVE-2019-1547", "CVE-2019-1563");
  script_xref(name:"SSA", value:"2019-254-03");

  script_name(english:"Slackware 14.2 / current : openssl (SSA:2019-254-03)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Slackware host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"New openssl packages are available for Slackware 14.2 and -current to
fix security issues.");
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2019&m=slackware-security.428772
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a95338ad");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl and / or openssl-solibs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1563");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:openssl-solibs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:14.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Slackware Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (slackware_check(osver:"14.2", pkgname:"openssl", pkgver:"1.0.2t", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", pkgname:"openssl-solibs", pkgver:"1.0.2t", pkgarch:"i586", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"openssl", pkgver:"1.0.2t", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;
if (slackware_check(osver:"14.2", arch:"x86_64", pkgname:"openssl-solibs", pkgver:"1.0.2t", pkgarch:"x86_64", pkgnum:"1_slack14.2")) flag++;

if (slackware_check(osver:"current", pkgname:"openssl", pkgver:"1.1.1d", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", pkgname:"openssl-solibs", pkgver:"1.1.1d", pkgarch:"i586", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"openssl", pkgver:"1.1.1d", pkgarch:"x86_64", pkgnum:"1")) flag++;
if (slackware_check(osver:"current", arch:"x86_64", pkgname:"openssl-solibs", pkgver:"1.1.1d", pkgarch:"x86_64", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
