#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:1609-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(195336);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id(
    "CVE-2024-32039",
    "CVE-2024-32040",
    "CVE-2024-32041",
    "CVE-2024-32458",
    "CVE-2024-32459",
    "CVE-2024-32460"
  );
  script_xref(name:"IAVA", value:"2024-A-0259");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:1609-1");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : freerdp (SUSE-SU-2024:1609-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12 host has packages installed that are affected by
multiple vulnerabilities as referenced in the SUSE-SU-2024:1609-1 advisory.

  - FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients using a version of
    FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to integer overflow and out-of-bounds write. Versions
    3.5.0 and 2.11.6 patch the issue. As a workaround, do not use `/gfx` options (e.g. deactivate with
    `/bpp:32` or `/rfx` as it is on by default). (CVE-2024-32039)

  - FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients that use a version
    of FreeRDP prior to 3.5.0 or 2.11.6 and have connections to servers using the `NSC` codec are vulnerable
    to integer underflow. Versions 3.5.0 and 2.11.6 patch the issue. As a workaround, do not use the NSC codec
    (e.g. use `-nsc`). (CVE-2024-32040)

  - FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients that use a version
    of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and 2.11.6 patch
    the issue. As a workaround, deactivate `/gfx` (on by default, set `/bpp` or `/rfx` options instead.
    (CVE-2024-32041)

  - FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients that use a version
    of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and 2.11.6 patch
    the issue. As a workaround, use `/gfx` or `/rfx` modes (on by default, require server side support).
    (CVE-2024-32458)

  - FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based clients and servers that
    use a version of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to out-of-bounds read. Versions 3.5.0 and
    2.11.6 patch the issue. No known workarounds are available. (CVE-2024-32459)

  - FreeRDP is a free implementation of the Remote Desktop Protocol. FreeRDP based based clients using
    `/bpp:32` legacy `GDI` drawing path with a version of FreeRDP prior to 3.5.0 or 2.11.6 are vulnerable to
    out-of-bounds read. Versions 3.5.0 and 2.11.6 patch the issue. As a workaround, use modern drawing paths
    (e.g. `/rfx` or `/gfx` options). The workaround requires server side support. (CVE-2024-32460)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223293");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223294");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223295");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223297");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223298");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-May/035235.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32040");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32041");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32458");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32459");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-32460");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32460");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:freerdp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfreerdp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwinpr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:winpr2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED12|SLED_SAP12|SLES12|SLES_SAP12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED12 / SLED_SAP12 / SLES12 / SLES_SAP12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'freerdp-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-devel-2.1.2-12.44.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.44.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.44.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'winpr2-devel-2.1.2-12.44.1', 'sp':'5', 'release':'SLES_SAP12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-12.5']},
    {'reference':'freerdp-devel-2.1.2-12.44.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.44.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.44.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'winpr2-devel-2.1.2-12.44.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-sdk-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-proxy-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'freerdp-server-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libfreerdp2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLED12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']},
    {'reference':'libwinpr2-2.1.2-12.44.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-we-release-12.5', 'sles-release-12.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'freerdp / freerdp-devel / freerdp-proxy / freerdp-server / etc');
}
