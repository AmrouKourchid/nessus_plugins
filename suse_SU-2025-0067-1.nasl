#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0067-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213967);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/11");

  script_cve_id(
    "CVE-2024-47530",
    "CVE-2024-47537",
    "CVE-2024-47539",
    "CVE-2024-47543",
    "CVE-2024-47544",
    "CVE-2024-47545",
    "CVE-2024-47546",
    "CVE-2024-47596",
    "CVE-2024-47597",
    "CVE-2024-47598",
    "CVE-2024-47599",
    "CVE-2024-47601",
    "CVE-2024-47602",
    "CVE-2024-47603",
    "CVE-2024-47606",
    "CVE-2024-47613",
    "CVE-2024-47774",
    "CVE-2024-47775",
    "CVE-2024-47776",
    "CVE-2024-47777",
    "CVE-2024-47778",
    "CVE-2024-47834"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0067-1");

  script_name(english:"SUSE SLES15 Security Update : gstreamer-plugins-good (SUSE-SU-2025:0067-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2025:0067-1 advisory.

    - CVE-2024-47530: Fixed an uninitialized stack memory in Matroska/WebM demuxer. (boo#1234421)
    - CVE-2024-47537: Fixed an out-of-bounds write in isomp4/qtdemux.c. (boo#1234414)
    - CVE-2024-47539: Fixed an out-of-bounds write in convert_to_s334_1a. (boo#1234417)
    - CVE-2024-47543: Fixed an out-of-bounds write in qtdemux_parse_container. (boo#1234462)
    - CVE-2024-47544: Fixed a NULL-pointer dereferences in MP4/MOV demuxer CENC handling. (boo#1234473)
    - CVE-2024-47545: Fixed an integer underflow in FOURCC_strf parsing leading to out-of-bounds read.
    (boo#1234476)
    - CVE-2024-47546: Fixed an integer underflow in extract_cc_from_data leading to out-of-bounds read.
    (boo#1234477)
    - CVE-2024-47596: Fixed an integer underflow in MP4/MOV demuxer that can lead to out-of-bounds reads.
    (boo#1234424)
    - CVE-2024-47597: Fixed an out-of-bounds reads in MP4/MOV demuxer sample table parser (boo#1234425)
    - CVE-2024-47598: Fixed MP4/MOV sample table parser out-of-bounds read. (boo#1234426)
    - CVE-2024-47599: Fixed insufficient error handling in JPEG decoder that can lead to NULL-pointer
    dereferences. (boo#1234427)
    - CVE-2024-47601: Fixed a NULL-pointer dereference in Matroska/WebM demuxer. (boo#1234428)
    - CVE-2024-47602: Fixed a NULL-pointer dereferences and out-of-bounds reads in Matroska/WebM demuxer.
    (boo#1234432)
    - CVE-2024-47603: Fixed a NULL-pointer dereference in Matroska/WebM demuxer. (boo#1234433)
    - CVE-2024-47606: Avoid integer overflow when allocating sysmem. (bsc#1234449)
    - CVE-2024-47606: Fixed an integer overflows in MP4/MOV demuxer and memory allocator that can lead to out-
    of-bounds writes. (boo#1234449)
    - CVE-2024-47613: Fixed a NULL-pointer dereference in gdk-pixbuf decoder. (boo#1234447)
    - CVE-2024-47774: Fixed an integer overflow in AVI subtitle parser that leads to out-of-bounds reads.
    (boo#1234446)
    - CVE-2024-47775: Fixed various out-of-bounds reads in WAV parser. (boo#1234434)
    - CVE-2024-47776: Fixed various out-of-bounds reads in WAV parser. (boo#1234435)
    - CVE-2024-47777: Fixed various out-of-bounds reads in WAV parser. (boo#1234436)
    - CVE-2024-47778: Fixed various out-of-bounds reads in WAV parser. (boo#1234439)
    - CVE-2024-47834: Fixed a use-after-free in the Matroska demuxer that can cause crashes for certain input
    files. (boo#1234440)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234417");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234421");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234424");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234425");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234426");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234427");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234428");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234432");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234433");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234434");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234435");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234446");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234462");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234473");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1234477");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-January/020097.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dabe4527");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47530");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47537");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47539");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47543");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47544");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47546");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47596");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47597");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47598");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47599");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47601");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47602");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47613");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47774");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47776");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47777");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-47834");
  script_set_attribute(attribute:"solution", value:
"Update the affected gstreamer-plugins-good and / or gstreamer-plugins-good-lang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47613");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-good");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gstreamer-plugins-good-lang");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'gstreamer-plugins-good-1.20.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'gstreamer-plugins-good-lang-1.20.1-150400.3.9.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'gstreamer-plugins-good-1.20.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'gstreamer-plugins-good-1.20.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'gstreamer-plugins-good-lang-1.20.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'gstreamer-plugins-good-1.20.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'gstreamer-plugins-good-1.20.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'gstreamer-plugins-good-lang-1.20.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'gstreamer-plugins-good-1.20.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'gstreamer-plugins-good-1.20.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'gstreamer-plugins-good / gstreamer-plugins-good-lang');
}
