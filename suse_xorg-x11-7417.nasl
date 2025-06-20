#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53404);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2011-0465");
  script_xref(name:"IAVA", value:"2017-A-0098-S");

  script_name(english:"SuSE 10 Security Update : X11 (ZYPP Patch Number 7417)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"Remote attackers could execute arbitrary commands as root by assigning
specially crafted hostnames to X11 clients via XDMCP. (CVE-2011-0465)");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-0465.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 7417.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2025 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-Xnest-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-Xvfb-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-Xvnc-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-devel-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-100dpi-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-75dpi-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-cyrillic-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-scalable-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-syriac-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-libs-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-man-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-server-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"i586", reference:"xorg-x11-server-glx-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-Xnest-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-Xvfb-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-Xvnc-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-devel-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-100dpi-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-75dpi-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-cyrillic-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-scalable-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-syriac-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-libs-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-man-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-server-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"xorg-x11-server-glx-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-Xnest-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-Xvfb-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-Xvnc-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-devel-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-doc-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-100dpi-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-75dpi-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-cyrillic-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-scalable-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-fonts-syriac-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-libs-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-man-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-sdk-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-server-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"i586", reference:"xorg-x11-server-glx-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-Xnest-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-Xvfb-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-Xvnc-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-devel-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-doc-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-100dpi-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-75dpi-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-cyrillic-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-scalable-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-fonts-syriac-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-libs-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.68.70.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-man-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-sdk-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-server-6.9.0-50.68.70.3")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"xorg-x11-server-glx-6.9.0-50.68.70.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
