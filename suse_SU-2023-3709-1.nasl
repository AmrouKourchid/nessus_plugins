#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3709-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181739);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id(
    "CVE-2023-3748",
    "CVE-2023-38802",
    "CVE-2023-41358",
    "CVE-2023-41360",
    "CVE-2023-41909"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3709-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : frr (SUSE-SU-2023:3709-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:3709-1 advisory.

  - A flaw was found in FRRouting when parsing certain babeld unicast hello messages that are intended to be
    ignored. This issue may allow an attacker to send specially crafted hello messages with the unicast flag
    set, the interval field set to 0, or any TLV that contains a sub-TLV with the Mandatory flag set to enter
    an infinite loop and cause a denial of service. (CVE-2023-3748)

  - FRRouting FRR 7.5.1 through 9.0 and Pica8 PICOS 4.3.3.2 allow a remote attacker to cause a denial of
    service via a crafted BGP update with a corrupted attribute 23 (Tunnel Encapsulation). (CVE-2023-38802)

  - An issue was discovered in FRRouting FRR through 9.0. bgpd/bgp_packet.c processes NLRIs if the attribute
    length is zero. (CVE-2023-41358)

  - An issue was discovered in FRRouting FRR through 9.0. bgpd/bgp_packet.c can read the initial byte of the
    ORF header in an ahead-of-stream situation. (CVE-2023-41360)

  - An issue was discovered in FRRouting FRR through 9.0. bgp_nlri_parse_flowspec in bgpd/bgp_flowspec.c
    processes malformed requests with no attributes, leading to a NULL pointer dereference. (CVE-2023-41909)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213284");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214739");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215065");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-September/016260.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc262dae");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-3748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-38802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-41358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-41360");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-41909");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-41360");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:frr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:frr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrr_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrcares0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrfpm_pb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrospfapiclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrsnmp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfrrzmq0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmlag_pb0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'frr-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'frr-devel-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libfrr0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libfrr_pb0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libfrrcares0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libfrrfpm_pb0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libfrrospfapiclient0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libfrrsnmp0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libfrrzmq0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libmlag_pb0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'frr-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'frr-devel-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libfrr0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libfrr_pb0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libfrrcares0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libfrrfpm_pb0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libfrrospfapiclient0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libfrrsnmp0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libfrrzmq0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'libmlag_pb0-8.4-150500.4.8.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-server-applications-release-15.5', 'sles-release-15.5']},
    {'reference':'frr-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'frr-devel-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libfrr0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libfrr_pb0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libfrrcares0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libfrrfpm_pb0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libfrrospfapiclient0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libfrrsnmp0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libfrrzmq0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libmlag_pb0-8.4-150500.4.8.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'frr / frr-devel / libfrr0 / libfrr_pb0 / libfrrcares0 / etc');
}
