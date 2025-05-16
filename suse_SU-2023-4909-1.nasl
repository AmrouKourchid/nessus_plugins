#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4909-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(187159);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/21");

  script_cve_id("CVE-2023-47641");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4909-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : python-aiohttp (SUSE-SU-2023:4909-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by a vulnerability
as referenced in the SUSE-SU-2023:4909-1 advisory.

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

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217174");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-December/017488.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6bc9545");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-47641");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-aiohttp-doc and / or python3-aiohttp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47641");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-aiohttp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-aiohttp");
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
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP1/2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'python-aiohttp-doc-3.6.0-150100.3.12.1', 'sp':'1', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'1', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'python-aiohttp-doc-3.6.0-150100.3.12.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'python-aiohttp-doc-3.6.0-150100.3.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.1', 'SUSE-Manager-Proxy-release-4.0', 'SUSE-Manager-Server-release-4.0', 'sle-module-public-cloud-release-15.1', 'sles-release-15.1', 'suse-manager-server-release-4.0']},
    {'reference':'python-aiohttp-doc-3.6.0-150100.3.12.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.2', 'SUSE-Manager-Proxy-release-4.1', 'SUSE-Manager-Server-release-4.1', 'sle-module-public-cloud-release-15.2', 'sles-release-15.2', 'suse-manager-server-release-4.1']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.3', 'SUSE-Manager-Proxy-release-4.2', 'SUSE-Manager-Server-release-4.2', 'sle-module-public-cloud-release-15.3', 'sles-release-15.3', 'suse-manager-server-release-4.2']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-public-cloud-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-public-cloud-release-15.5', 'sles-release-15.5']},
    {'reference':'python-aiohttp-doc-3.6.0-150100.3.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'python-aiohttp-doc-3.6.0-150100.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'python3-aiohttp-3.6.0-150100.3.12.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python-aiohttp-doc / python3-aiohttp');
}
