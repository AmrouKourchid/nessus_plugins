##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:5369. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(143603);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2020-8695", "CVE-2020-8696", "CVE-2020-8698");
  script_xref(name:"RHSA", value:"2020:5369");

  script_name(english:"RHEL 8 : microcode_ctl (RHSA-2020:5369)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has a package installed that is affected by multiple vulnerabilities as
referenced in the RHSA-2020:5369 advisory.

    The microcode_ctl packages provide microcode updates for Intel.

    Security Fix(es):

    * hw: Information disclosure issue in Intel SGX via RAPL interface (CVE-2020-8695)

    * hw: Vector Register Leakage-Active (CVE-2020-8696)

    * hw: Fast forward store predictor (CVE-2020-8698)

    Bug Fix(es) and Enhancement(s):

    * Update Intel CPU microcode to microcode-20201027 release, addresses:
      - Addition of 06-55-0b/0xbf (CPX-SP A1) microcode at revision 0x700001e;
      - Addition of 06-8c-01/0x80 (TGL-UP3/UP4 B1) microcode at revision 0x68;
      - Addition of 06-a5-02/0x20 (CML-H R1) microcode at revision 0xe0;
      - Addition of 06-a5-03/0x22 (CML-S 6+2 G1) microcode at revision 0xe0;
      - Addition of 06-a5-05/0x22 (CML-S 10+2 Q0) microcode at revision 0xe0;
      - Addition of 06-a6-01/0x80 (CML-U 6+2 v2 K0) microcode at revision
        0xe0;
      - Update of 06-4e-03/0xc0 (SKL-U/U 2+3e/Y D0/K1) microcode (in
        intel-06-4e-03/intel-ucode/06-4e-03) from revision 0xdc up to 0xe2;
      - Update of 06-55-04/0xb7 (SKX-D/SP/W/X H0/M0/M1/U0) microcode (in
        intel-06-55-04/intel-ucode/06-55-04) from revision 0x2006906 up
        to 0x2006a08;
      - Update of 06-5e-03/0x36 (SKL-H/S/Xeon E3 N0/R0/S0) microcode (in
        intel-06-5e-03/intel-ucode/06-5e-03) from revision 0xdc up to 0xe2;
      - Update of 06-8e-09/0x10 (AML-Y 2+2 H0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xd6 up
        to 0xde;
      - Update of 06-8e-09/0xc0 (KBL-U/U 2+3e/Y H0/J1) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-09) from revision 0xd6 up
        to 0xde;
      - Update of 06-8e-0a/0xc0 (CFL-U 4+3e D0, KBL-R Y0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0a) from revision 0xd6 up
        to 0xe0;
      - Update of 06-8e-0b/0xd0 (WHL-U W0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0b) from revision 0xd6 up
        to 0xde;
      - Update of 06-8e-0c/0x94 (AML-Y 4+2 V0, CML-U 4+2 V0, WHL-U V0)
        microcode (in intel-06-8e-9e-0x-dell/intel-ucode/06-8e-0c) from
        revision 0xd6 up to 0xde;
      - Update of 06-9e-09/0x2a (KBL-G/H/S/X/Xeon E3 B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-09) from revision 0xd6 up
        to 0xde;
      - Update of 06-9e-0a/0x22 (CFL-H/S/Xeon E U0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0a) from revision 0xd6 up
        to 0xde;
      - Update of 06-9e-0b/0x02 (CFL-E/H/S B0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0b) from revision 0xd6 up
        to 0xde;
      - Update of 06-9e-0c/0x22 (CFL-H/S/Xeon E P0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0c) from revision 0xd6 up
        to 0xde;
      - Update of 06-9e-0d/0x22 (CFL-H/S/Xeon E R0) microcode (in
        intel-06-8e-9e-0x-dell/intel-ucode/06-9e-0d) from revision 0xd6 up
        to 0xde;
      - Update of 06-3f-02/0x6f (HSX-E/EN/EP/EP 4S C0/C1/M1/R2) microcode
        from revision 0x43 up to 0x44;
      - Update of 06-55-03/0x97 (SKX-SP B1) microcode from revision 0x1000157
        up to 0x1000159;
      - Update of 06-55-06/0xbf (CLX-SP B0) microcode from revision 0x4002f01
        up to 0x4003003;
      - Update of 06-55-07/0xbf (CLX-SP/W/X B1/L1) microcode from revision
        0x5002f01 up to 0x5003003;
      - Update of 06-5c-09/0x03 (APL D0) microcode from revision 0x38 up
        to 0x40;
      - Update of 06-5c-0a/0x03 (APL B1/F1) microcode from revision 0x16 up
        to 0x1e;
      - Update of 06-7a-08/0x01 (GLK-R R0) microcode from revision 0x16 up
        to 0x18;
      - Update of 06-7e-05/0x80 (ICL-U/Y D1) microcode from revision 0x78
        up to 0xa0;
      - Update of 06-a6-00/0x80 (CML-U 6+2 A0) microcode from revision 0xca
        up to 0xe0.

    * Add README file to the documentation directory.

    * Add publicly-sourced codenames list to supply to gen_provides.sh; update
      the latter to handle the somewhat different format.

    * Add SUMMARY.intel-ucode file containing metadata information from
      the microcode file headers.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_5369.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a621200e");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:5369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1828583");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890355");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1890356");
  script_set_attribute(attribute:"solution", value:
"Update the affected microcode_ctl package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8698");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 212);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:microcode_ctl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '8.1')) audit(AUDIT_OS_NOT, 'Red Hat 8.1', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/e4s/rhel8/8.1/x86_64/baseos/debug',
      'content/e4s/rhel8/8.1/x86_64/baseos/os',
      'content/e4s/rhel8/8.1/x86_64/baseos/source/SRPMS',
      'content/eus/rhel8/8.1/x86_64/baseos/debug',
      'content/eus/rhel8/8.1/x86_64/baseos/os',
      'content/eus/rhel8/8.1/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'microcode_ctl-20190618-1.20201112.1.el8_1', 'sp':'1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var subscription_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in the Red Hat Enterprise Linux\n' +
    'Extended Update Support repository.\n' +
    'Access to this repository requires a paid RHEL subscription.\n';
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = subscription_caveat + rpm_report_get() + redhat_report_repo_caveat();
  else extra = subscription_caveat + rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'microcode_ctl');
}
