#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0577-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(190879);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id(
    "CVE-2023-47627",
    "CVE-2023-47641",
    "CVE-2024-23334",
    "CVE-2024-23829"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0577-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : python-aiohttp, python-time-machine (SUSE-SU-2024:0577-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has a package installed that is
affected by multiple vulnerabilities as referenced in the SUSE-SU-2024:0577-1 advisory.

  - aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. The HTTP parser in AIOHTTP
    has numerous problems with header parsing, which could lead to request smuggling. This parser is only used
    when AIOHTTP_NO_EXTENSIONS is enabled (or not using a prebuilt wheel). These bugs have been addressed in
    commit `d5c12ba89` which has been included in release version 3.8.6. Users are advised to upgrade. There
    are no known workarounds for these issues. (CVE-2023-47627)

  - aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. Affected versions of
    aiohttp have a security vulnerability regarding the inconsistent interpretation of the http protocol.
    HTTP/1.1 is a persistent protocol, if both Content-Length(CL) and Transfer-Encoding(TE) header values are
    present it can lead to incorrect interpretation of two entities that parse the HTTP and we can poison
    other sockets with this incorrect interpretation. A possible Proof-of-Concept (POC) would be a
    configuration with a reverse proxy(frontend) that accepts both CL and TE headers and aiohttp as backend.
    As aiohttp parses anything with chunked, we can pass a chunked123 as TE, the frontend entity will ignore
    this header and will parse Content-Length. The impact of this vulnerability is that it is possible to
    bypass any proxy rule, poisoning sockets to other users like passing Authentication Headers, also if it is
    present an Open Redirect an attacker could combine it to redirect random users to another website and log
    the request. This vulnerability has been addressed in release 3.8.0 of aiohttp. Users are advised to
    upgrade. There are no known workarounds for this vulnerability. (CVE-2023-47641)

  - aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. When using aiohttp as a
    web server and configuring static routes, it is necessary to specify the root path for static files.
    Additionally, the option 'follow_symlinks' can be used to determine whether to follow symbolic links
    outside the static root directory. When 'follow_symlinks' is set to True, there is no validation to check
    if reading a file is within the root directory. This can lead to directory traversal vulnerabilities,
    resulting in unauthorized access to arbitrary files on the system, even when symlinks are not present.
    Disabling follow_symlinks and using a reverse proxy are encouraged mitigations. Version 3.9.2 fixes this
    issue. (CVE-2024-23334)

  - aiohttp is an asynchronous HTTP client/server framework for asyncio and Python. Security-sensitive parts
    of the Python HTTP parser retained minor differences in allowable character sets, that must trigger error
    handling to robustly match frame boundaries of proxies in order to protect against injection of additional
    requests. Additionally, validation could trigger exceptions that were not handled consistently with
    processing of other malformed input. Being more lenient than internet standards require could, depending
    on deployment environment, assist in request smuggling. The unhandled exception could cause excessive
    resource consumption on the application server and/or its logging facilities. This vulnerability exists
    due to an incomplete fix for CVE-2023-47627. Version 3.9.2 fixes this vulnerability. (CVE-2024-23829)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217174");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217181");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219342");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-February/017982.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b97066ec");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47627");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47641");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23334");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-23829");
  script_set_attribute(attribute:"solution", value:
"Update the affected python311-aiohttp package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-23334");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python311-aiohttp");
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
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-python3-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python311-aiohttp-3.9.3-150400.10.14.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python311-aiohttp');
}
