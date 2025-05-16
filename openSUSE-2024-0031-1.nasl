#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2024:0031-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(189492);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/05");

  script_cve_id(
    "CVE-2023-49084",
    "CVE-2023-49085",
    "CVE-2023-49086",
    "CVE-2023-49088",
    "CVE-2023-50250",
    "CVE-2023-51448"
  );

  script_name(english:"openSUSE 15 Security Update : cacti, cacti-spine (openSUSE-SU-2024:0031-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2024:0031-1 advisory.

  - Cacti is a robust performance and fault management framework and a frontend to RRDTool - a Time Series
    Database (TSDB). While using the detected SQL Injection and insufficient processing of the include file
    path, it is possible to execute arbitrary code on the server. Exploitation of the vulnerability is
    possible for an authorized user. The vulnerable component is the `link.php`. Impact of the vulnerability
    execution of arbitrary code on the server. (CVE-2023-49084)

  - Cacti provides an operational monitoring and fault management framework. In versions 1.2.25 and prior, it
    is possible to execute arbitrary SQL code through the `pollers.php` script. An authorized user may be able
    to execute arbitrary SQL code. The vulnerable component is the `pollers.php`. Impact of the vulnerability
    - arbitrary SQL code execution. As of time of publication, a patch does not appear to exist.
    (CVE-2023-49085)

  - Cacti is a robust performance and fault management framework and a frontend to RRDTool - a Time Series
    Database (TSDB). Bypassing an earlier fix (CVE-2023-39360) that leads to a DOM XSS attack. Exploitation of
    the vulnerability is possible for an authorized user. The vulnerable component is the `graphs_new.php`.
    Impact of the vulnerability - execution of arbitrary javascript code in the attacked user's browser. This
    issue has been patched in version 1.2.26. (CVE-2023-49086)

  - Cacti is an open source operational monitoring and fault management framework. The fix applied for
    CVE-2023-39515 in version 1.2.25 is incomplete as it enables an adversary to have a victim browser execute
    malicious code when a victim user hovers their mouse over the malicious data source path in
    `data_debug.php`. To perform the cross-site scripting attack, the adversary needs to be an authorized
    cacti user with the following permissions: `General Administration>Sites/Devices/Data`. The victim of this
    attack could be any account with permissions to view `http://<HOST>/cacti/data_debug.php`. As of time of
    publication, no complete fix has been included in Cacti. (CVE-2023-49088)

  - Cacti is an open source operational monitoring and fault management framework. A reflection cross-site
    scripting vulnerability was discovered in version 1.2.25. Attackers can exploit this vulnerability to
    perform actions on behalf of other users. The vulnerability is found in `templates_import.php.` When
    uploading an xml template file, if the XML file does not pass the check, the server will give a JavaScript
    pop-up prompt, which contains unfiltered xml template file name, resulting in XSS. An attacker exploiting
    this vulnerability could execute actions on behalf of other users. This ability to impersonate users could
    lead to unauthorized changes to settings. As of time of publication, no patched versions are available.
    (CVE-2023-50250)

  - Cacti provides an operational monitoring and fault management framework. Version 1.2.25 has a Blind SQL
    Injection (SQLi) vulnerability within the SNMP Notification Receivers feature in the file
    `managers.php'`. An authenticated attacker with the Settings/Utilities permission can send a crafted
    HTTP GET request to the endpoint `/cacti/managers.php'` with an SQLi payload in the
    `selected_graphs_array'` HTTP GET parameter. As of time of publication, no patched versions exist.
    (CVE-2023-51448)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218378");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218380");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218381");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/IZJKJNYP7JFJ3XMRIGZT22J5DIAVPSY7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e962cfc6");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49084");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49085");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49086");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-49088");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-50250");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51448");
  script_set_attribute(attribute:"solution", value:
"Update the affected cacti and / or cacti-spine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-51448");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti RCE via SQLi in pollers.php');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'cacti-1.2.26-bp155.2.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cacti-spine-1.2.26-bp155.2.6.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cacti / cacti-spine');
}
