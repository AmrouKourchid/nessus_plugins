#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-SUSE-RU-2025:0791-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(232319);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-8775");
  script_xref(name:"SuSE", value:"SUSE-RU-2025:0791-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 : Recommended update 4.3.15 for Multi-Linux Manager Client Tools (SUSE-SU-SUSE-RU-2025:0791-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by a vulnerability as
referenced in the SUSE-SU-SUSE-RU-2025:0791-1 advisory.

    ansible:

    - Security issues fixed:
      * CVE-2024-8775: Fixed issue where sensitive information stored in Ansible Vault files
        could be exposed in plaintext (bsc#1230601)

    spacewalk-client-tools:

    - Version 4.3.22-0
      * Allow translation to wrap strings as weblate forces it
      * Show Source String change for translations

    uyuni-proxy-systemd-services:

    - Version 4.3.15-0
      * Update to Multi-Linux Manager 4.3.15

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230601");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-March/038632.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-8775");
  script_set_attribute(attribute:"solution", value:
"Update the affected ansible, ansible-doc, ansible-test and / or uyuni-proxy-systemd-services packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8775");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ansible-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uyuni-proxy-systemd-services");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ansible-2.9.27-150000.1.20.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'ansible-doc-2.9.27-150000.1.20.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'uyuni-proxy-systemd-services-4.3.15-150000.1.30.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Proxy-release-4.3']},
    {'reference':'ansible-2.9.27-150000.1.20.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ansible-doc-2.9.27-150000.1.20.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'ansible-test-2.9.27-150000.1.20.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible / ansible-doc / ansible-test / uyuni-proxy-systemd-services');
}
