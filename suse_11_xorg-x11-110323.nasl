#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53316);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2011-0465");
  script_xref(name:"IAVA", value:"2017-A-0098-S");

  script_name(english:"SuSE 11.1 Security Update : X11 (SAT Patch Number 4199)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 11 host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Remote attackers could execute arbitrary commands as root by assigning
specially crafted hostnames to X11 clients via XDMCP. (CVE-2011-0465)");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=674733");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-0465.html");
  script_set_attribute(attribute:"solution", value:
"Apply SAT patch number 4199.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-7.4-9.39.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-xauth-7.4-9.39.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-7.4-9.39.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-xauth-7.4-9.39.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-7.4-9.39.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-xauth-7.4-9.39.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
