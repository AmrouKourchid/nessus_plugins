#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:3852-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155808);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/13");

  script_cve_id(
    "CVE-2021-28702",
    "CVE-2021-28704",
    "CVE-2021-28705",
    "CVE-2021-28706",
    "CVE-2021-28707",
    "CVE-2021-28708",
    "CVE-2021-28709"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:3852-1");
  script_xref(name:"IAVB", value:"2021-B-0044-S");
  script_xref(name:"IAVB", value:"2021-B-0068-S");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : xen (SUSE-SU-2021:3852-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLES12 / SLES_SAP12 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2021:3852-1 advisory.

  - PCI devices with RMRRs not deassigned correctly Certain PCI devices in a system might be assigned Reserved
    Memory Regions (specified via Reserved Memory Region Reporting, RMRR). These are typically used for
    platform tasks such as legacy USB emulation. If such a device is passed through to a guest, then on guest
    shutdown the device is not properly deassigned. The IOMMU configuration for these devices which are not
    properly deassigned ends up pointing to a freed data structure, including the IO Pagetables. Subsequent
    DMA or interrupts from the device will have unpredictable behaviour, ranging from IOMMU faults to memory
    corruption. (CVE-2021-28702)

  - PoD operations on misaligned GFNs T[his CNA information record relates to multiple CVEs; the text explains
    which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be started in populate-
    on-demand (PoD) mode, to provide a way for them to later easily have more memory assigned. Guests are
    permitted to control certain P2M aspects of individual pages via hypercalls. These hypercalls may act on
    ranges of pages specified via page orders (resulting in a power-of-2 number of pages). The implementation
    of some of these hypercalls for PoD does not enforce the base page frame number to be suitably aligned for
    the specified order, yet some code involved in PoD handling actually makes such an assumption. These
    operations are XENMEM_decrease_reservation (CVE-2021-28704) and XENMEM_populate_physmap (CVE-2021-28707),
    the latter usable only by domains controlling the guest, i.e. a de-privileged qemu or a stub domain.
    (Patch 1, combining the fix to both these two issues.) In addition handling of XENMEM_decrease_reservation
    can also trigger a host crash when the specified page order is neither 4k nor 2M nor 1G (CVE-2021-28708,
    patch 2). (CVE-2021-28704, CVE-2021-28707, CVE-2021-28708)

  - issues with partially successful P2M updates on x86 T[his CNA information record relates to multiple CVEs;
    the text explains which aspects/vulnerabilities correspond to which CVE.] x86 HVM and PVH guests may be
    started in populate-on-demand (PoD) mode, to provide a way for them to later easily have more memory
    assigned. Guests are permitted to control certain P2M aspects of individual pages via hypercalls. These
    hypercalls may act on ranges of pages specified via page orders (resulting in a power-of-2 number of
    pages). In some cases the hypervisor carries out the requests by splitting them into smaller chunks. Error
    handling in certain PoD cases has been insufficient in that in particular partial success of some
    operations was not properly accounted for. There are two code paths affected - page removal
    (CVE-2021-28705) and insertion of new pages (CVE-2021-28709). (We provide one patch which combines the fix
    to both issues.) (CVE-2021-28705, CVE-2021-28709)

  - guests may exceed their designated memory limit When a guest is permitted to have close to 16TiB of
    memory, it may be able to issue hypercalls to increase its memory allocation beyond the administrator
    established limit. This is a result of a calculation done with 32-bit precision, which may overflow. It
    would then only be the overflowed (and hence small) number which gets compared against the established
    upper bound. (CVE-2021-28706)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1027519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191363");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1191510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1192559");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28702");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28704");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28705");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28706");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28707");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28708");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-28709");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-December/009796.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c8e95d0");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28709");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-28708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'xen-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xen-doc-html-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xen-libs-32bit-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xen-libs-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xen-tools-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xen-tools-domU-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'xen-devel-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5']},
    {'reference':'xen-devel-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5']},
    {'reference':'xen-devel-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5']},
    {'reference':'xen-devel-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5']},
    {'reference':'xen-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'xen-doc-html-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'xen-libs-32bit-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'xen-libs-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'xen-tools-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'xen-tools-domU-4.12.4_16-3.55.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'xen / xen-devel / xen-doc-html / xen-libs / xen-libs-32bit / etc');
}
