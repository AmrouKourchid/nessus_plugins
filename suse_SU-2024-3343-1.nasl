#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3343-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207490);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/20");

  script_cve_id(
    "CVE-2021-25743",
    "CVE-2023-2727",
    "CVE-2023-2728",
    "CVE-2023-39325",
    "CVE-2023-44487",
    "CVE-2023-45288",
    "CVE-2024-0793",
    "CVE-2024-3177",
    "CVE-2024-24786"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3343-1");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"SUSE SLES15 Security Update : kubernetes1.24 (SUSE-SU-2024:3343-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3343-1 advisory.

    - CVE-2021-25743: escape, meta and control sequences in raw data output to terminal not neutralized.
    (bsc#1194400)
    - CVE-2023-2727: bypass of policies imposed by the ImagePolicyWebhook admission plugin. (bsc#1211630)
    - CVE-2023-2728: bypass of the mountable secrets policy enforced by the ServiceAccount admission plugin.
    (bsc#1211631)
    - CVE-2023-39325: go1.20: excessive resource consumption when dealing with rapid stream resets.
    (bsc#1229869)
    - CVE-2023-44487: google.golang.org/grpc, kube-apiserver: HTTP/2 rapid reset vulnerability. (bsc#1229869)
    - CVE-2023-45288: golang.org/x/net: excessive CPU consumption when processing unlimited sets of headers.
    (bsc#1229869)
    - CVE-2024-0793: kube-controller-manager pod crash when processing malformed HPA v1 manifests.
    (bsc#1219964)
    - CVE-2024-3177: bypass of the mountable secrets policy enforced by the ServiceAccount admission plugin.
    (bsc#1222539)
    - CVE-2024-24786: github.com/golang/protobuf: infinite loop when unmarshaling invalid JSON. (bsc#1229867)

    Bug fixes:

    - Use -trimpath in non-DBG mode for reproducible builds. (bsc#1062303)
    - Fix multiple issues for successful `kubeadm init` run. (bsc#1214406)
    - Update go to version 1.22.5 in build requirements. (bsc#1229858)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1062303");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214406");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216123");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222539");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1226136");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229867");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230323");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/036980.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5c1c1b43");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25743");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2727");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2728");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39325");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-44487");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45288");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-0793");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24786");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-3177");
  script_set_attribute(attribute:"solution", value:
"Update the affected kubernetes1.24-client and / or kubernetes1.24-client-common packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25743");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-2728");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kubernetes1.24-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kubernetes1.24-client-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kubernetes1.24-client-1.24.17-150300.7.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kubernetes1.24-client-common-1.24.17-150300.7.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kubernetes1.24-client-1.24.17-150300.7.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kubernetes1.24-client-1.24.17-150300.7.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kubernetes1.24-client-common-1.24.17-150300.7.6.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kubernetes1.24-client-common-1.24.17-150300.7.6.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kubernetes1.24-client-1.24.17-150300.7.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kubernetes1.24-client-common-1.24.17-150300.7.6.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kubernetes1.24-client / kubernetes1.24-client-common');
}
