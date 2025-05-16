#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3771-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(209968);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/29");

  script_cve_id(
    "CVE-2024-4067",
    "CVE-2024-4068",
    "CVE-2024-9014",
    "CVE-2024-38355",
    "CVE-2024-38998",
    "CVE-2024-38999",
    "CVE-2024-39338",
    "CVE-2024-43788",
    "CVE-2024-48948",
    "CVE-2024-48949"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3771-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : pgadmin4 (SUSE-SU-2024:3771-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:3771-1 advisory.

    - CVE-2024-38355: Fixed socket.io: unhandled 'error' event (bsc#1226967)
    - CVE-2024-38998: Fixed requirejs: prototype pollution via function config (bsc#1227248)
    - CVE-2024-38999: Fixed requirejs: prototype pollution via function s.contexts._.configure (bsc#1227252)
    - CVE-2024-39338: Fixed axios: server-side request forgery due to requests for path relative URLs being
    processed as protocol relative URLs in axios (bsc#1229423)
    - CVE-2024-4067: Fixed micromatch: vulnerable to Regular Expression Denial of Service (ReDoS)
    (bsc#1224366)
    - CVE-2024-4068: Fixed braces: fails to limit the number of characters it can handle, which could lead to
    Memory Exhaustion (bsc#1224295)
    - CVE-2024-43788: Fixed webpack: DOM clobbering gadget in AutoPublicPathRuntimeModule could lead to XSS
    (bsc#1229861)
    - CVE-2024-48948: Fixed elliptic: ECDSA signature verification error due to leading zero may reject
    legitimate transactions in elliptic (bsc#1231684)
    - CVE-2024-48949: Fixed elliptic: Missing Validation in Elliptic's EDDSA Signature Verification
    (bsc#1231564)
    - CVE-2024-9014: Fixed OAuth2 issue that could lead to information leak (bsc#1230928)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226967");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227248");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227252");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1231684");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-October/019689.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47d06711");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38355");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38998");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-38999");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-39338");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-4067");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-4068");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48948");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-48949");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-9014");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38998");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-48949");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pgadmin4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:pgadmin4-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:system-user-pgadmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'pgadmin4-8.5-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'pgadmin4-8.5-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'pgadmin4-doc-8.5-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'pgadmin4-doc-8.5-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'system-user-pgadmin-8.5-150600.3.6.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'system-user-pgadmin-8.5-150600.3.6.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'pgadmin4-8.5-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'pgadmin4-8.5-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'pgadmin4-doc-8.5-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'pgadmin4-doc-8.5-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'system-user-pgadmin-8.5-150600.3.6.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'system-user-pgadmin-8.5-150600.3.6.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-python3-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'pgadmin4-8.5-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'pgadmin4-cloud-8.5-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'pgadmin4-desktop-8.5-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'pgadmin4-doc-8.5-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'pgadmin4-web-uwsgi-8.5-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'system-user-pgadmin-8.5-150600.3.6.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pgadmin4 / pgadmin4-cloud / pgadmin4-desktop / pgadmin4-doc / etc');
}
