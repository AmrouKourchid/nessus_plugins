#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:0276-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(171058);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/14");

  script_cve_id("CVE-2022-44570", "CVE-2022-44571", "CVE-2022-44572");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:0276-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : rubygem-rack (SUSE-SU-2023:0276-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:0276-1 advisory.

  - A denial of service vulnerability in the Range header parsing component of Rack >= 1.5.0. A Carefully
    crafted input can cause the Range header parsing component in Rack to take an unexpected amount of time,
    possibly resulting in a denial of service attack vector. Any applications that deal with Range requests
    (such as streaming applications, or applications that serve files) may be impacted. (CVE-2022-44570)

  - There is a denial of service vulnerability in the Content-Disposition parsingcomponent of Rack fixed in
    2.0.9.2, 2.1.4.2, 2.2.4.1, 3.0.0.1. This could allow an attacker to craft an input that can cause Content-
    Disposition header parsing in Rackto take an unexpected amount of time, possibly resulting in a denial
    ofservice attack vector. This header is used typically used in multipartparsing. Any applications that
    parse multipart posts using Rack (virtuallyall Rails applications) are impacted. (CVE-2022-44571)

  - A denial of service vulnerability in the multipart parsing component of Rack fixed in 2.0.9.2, 2.1.4.2,
    2.2.4.1 and 3.0.0.1 could allow an attacker tocraft input that can cause RFC2183 multipart boundary
    parsing in Rack to take an unexpected amount of time, possibly resulting in a denial of service attack
    vector. Any applications that parse multipart posts using Rack (virtually all Rails applications) are
    impacted. (CVE-2022-44572)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207596");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-44570");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-44571");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-44572");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-February/013629.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f7fb995");
  script_set_attribute(attribute:"solution", value:
"Update the affected ruby2.5-rubygem-rack, ruby2.5-rubygem-rack-doc and / or ruby2.5-rubygem-rack-testsuite packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44572");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ruby2.5-rubygem-rack");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3/4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(1|2|3|4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP1/2/3/4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'1', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.1', 'sle-ha-release-15.1', 'sles-release-15.1']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.2', 'sle-ha-release-15.2', 'sles-release-15.2']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'sle-ha-release-15.3', 'sles-release-15.3']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'sle-ha-release-15.4', 'sles-release-15.4']},
    {'reference':'ruby2.5-rubygem-rack-2.0.8-150000.3.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-rack-doc-2.0.8-150000.3.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ruby2.5-rubygem-rack-testsuite-2.0.8-150000.3.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby2.5-rubygem-rack / ruby2.5-rubygem-rack-doc / etc');
}
