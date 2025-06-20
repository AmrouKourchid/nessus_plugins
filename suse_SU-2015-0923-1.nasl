#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0923-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83757);
  script_version("2.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/28");

  script_cve_id(
    "CVE-2015-2751",
    "CVE-2015-2752",
    "CVE-2015-3340",
    "CVE-2015-3456"
  );
  script_bugtraq_id(
    73443,
    73448,
    74248,
    74640
  );
  script_xref(name:"IAVA", value:"2015-A-0115-S");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2015:0923-1) (Venom)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"XEN was updated to fix two security issues and bugs.

Security issues fixed :

  - CVE-2015-3340: Xen did not initialize certain fields,
    which allowed certain remote service domains to obtain
    sensitive information from memory via a (1)
    XEN_DOMCTL_gettscinfo or (2)
    XEN_SYSCTL_getdomaininfolist request.

  - CVE-2015-2751: Xen, when using toolstack disaggregation,
    allowed remote domains with partial management control
    to cause a denial of service (host lock) via unspecified
    domctl operations.

  - CVE-2015-2752: The XEN_DOMCTL_memory_mapping hypercall
    in Xen, when using a PCI passthrough device, was not
    preemptable, which allowed local x86 HVM domain users to
    cause a denial of service (host CPU consumption) via a
    crafted request to the device model (qemu-dm).

  - CVE-2015-3456: Fixed a buffer overflow in the floppy
    drive emulation, which could be used to denial of
    service attacks or potential code execution against the
    host.

Bugs fixed :

  - xentop: Fix memory leak on read failure

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=922705");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=922709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=927967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=929339");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2751/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-2752/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-3340/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2015-3456/");
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150923-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbe2b7e6");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-206=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-206=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-206=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-doc-html-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.2_04_k3.12.39_47-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.2_04_k3.12.39_47-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"xen-tools-domU-debuginfo-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-debugsource-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-4.4.2_04_k3.12.39_47-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.2_04_k3.12.39_47-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-32bit-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.2_04-18.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xen-libs-debuginfo-4.4.2_04-18.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
