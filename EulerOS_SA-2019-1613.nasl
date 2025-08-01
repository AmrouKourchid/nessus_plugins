#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(125565);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/17");

  script_cve_id(
    "CVE-2018-10194",
    "CVE-2019-3835",
    "CVE-2019-3838",
    "CVE-2019-3839",
    "CVE-2019-6116"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : ghostscript (EulerOS-SA-2019-1613)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ghostscript package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - Ghostscript is a set of software that provides a
    PostScript interpreter, a set of C procedures (the
    Ghostscript library, which implements the graphics
    capabilities in the PostScript language) and an
    interpreter for Portable Document Format (PDF) files.
    Ghostscript translates PostScript code into many
    common, bitmapped formats, like those understood by
    your printer or screen. Ghostscript is normally used to
    display PostScript files and to print PostScript files
    to non-PostScript printers.Security Fix(es):It was
    found that the forceput operator could be extracted
    from the DefineResource method. A specially crafted
    PostScript file could use this flaw in order to, for
    example, have access to the file system outside of the
    constrains imposed by -dSAFER.(CVE-2019-3838)t was
    found that the superexec operator was available in the
    internal dictionary. A specially crafted PostScript
    file could use this flaw in order to, for example, have
    access to the file system outside of the constrains
    imposed by -dSAFER.(CVE-2019-3835)It was found that
    ghostscript could leak sensitive operators on the
    operand stack when a pseudo-operator pushes a
    subroutine. A specially crafted PostScript file could
    use this flaw to escape the -dSAFER protection in order
    to, for example, have access to the file system outside
    of the SAFER constraints.(CVE-2019-6116)It was found
    that some privileged operators remained accessible from
    various places after the CVE-2019-6116 fix. A specially
    crafted PostScript file could use this flaw in order
    to, for example, have access to the file system outside
    of the constrains imposed by -dSAFER.(CVE-2019-3839)The
    set_text_distance function in devices/vector/gdevpdts.c
    in the pdfwrite component in Artifex Ghostscript
    through 9.22 does not prevent overflows in
    text-positioning calculation, which allows remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted PDF document.(CVE-2018-10194)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1613
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eeac63cd");
  script_set_attribute(attribute:"solution", value:
"Update the affected ghostscript packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6116");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["ghostscript-9.07-31.6.h6"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
