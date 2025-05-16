#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-18476abd7e
#

include('compat.inc');

if (description)
{
  script_id(179978);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2023-32002",
    "CVE-2023-32003",
    "CVE-2023-32004",
    "CVE-2023-32005",
    "CVE-2023-32006",
    "CVE-2023-32558",
    "CVE-2023-32559"
  );
  script_xref(name:"FEDORA", value:"2023-18476abd7e");

  script_name(english:"Fedora 37 : nodejs16 / nodejs18 / nodejs20 (2023-18476abd7e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-18476abd7e advisory.

    https://nodejs.org/en/blog/vulnerability/august-2023-security-releases

    Security releases available
    Updates are now available for the v16.x, v18.x, and v20.x Node.js release lines for the following issues.

    Permissions policies can be bypassed via Module._load (HIGH)(CVE-2023-32002)
    The use of Module._load() can bypass the policy mechanism and require modules outside of the policy.json
    definition for a given module.

    Please note that at the time this CVE was issued, the policy mechanism is an experimental feature of
    Node.js.

    Impacts:

    This vulnerability affects all users using the experimental policy mechanism in all active release lines:
    16.x, 18.x and, 20.x.
    Thank you, to mattaustin for reporting this vulnerability and thank you Rafael Gonzaga and Bradley Farias
    for fixing it.

    Permission model bypass by specifying a path traversal sequence in a Buffer (HIGH)(CVE-2023-32004)
    A vulnerability has been discovered in Node.js version 20, specifically within the experimental permission
    model. This flaw relates to improper handling of Buffers in file system APIs causing a traversal path to
    bypass when verifying file permissions.

    Please note that at the time this CVE was issued, the permission model is an experimental feature of
    Node.js.

    Impacts:

    This vulnerability affects all users using the experimental permission model in Node.js 20.
    Thank you, to Axel Chong for reporting this vulnerability and thank you Rafael Gonzaga for fixing it.

    process.binding() can bypass the permission model through path traversal (HIGH)(CVE-2023-32558)
    The use of the deprecated API process.binding() can bypass the permission model through path traversal.

    Please note that at the time this CVE was issued, the permission model is an experimental feature of
    Node.js.

    Impacts:

    This vulnerability affects all users using the experimental permission model in Node.js 20.
    Thank you to Rafael Gonzaga for reporting and fixing this vulnerability.

    Permissions policies can impersonate other modules in using module.constructor.createRequire()
    (MEDIUM)(CVE-2023-32006)
    The use of module.constructor.createRequire() can bypass the policy mechanism and require modules outside
    of the policy.json definition for a given module.

    Please note that at the time this CVE was issued, the policy mechanism is an experimental feature of
    Node.js.

    Impacts:

    This vulnerability affects all users using the experimental policy mechanism in all active release lines:
    16.x, 18.x and, 20.x.
    Thank you, to Axel Chong for reporting this vulnerability and thank you Rafael Gonzaga and Bradley Farias
    for fixing it.

    Permissions policies can be bypassed via process.binding (MEDIUM)(CVE-2023-32559)
    The use of the deprecated API process.binding() can bypass the policy mechanism by requiring internal
    modules and eventually take advantage of process.binding('spawn_sync') run arbitrary code, outside of the
    limits defined in a policy.json file.

    Please note that at the time this CVE was issued, the policy is an experimental feature of Node.js.

    Impacts

    This vulnerability affects all users using the experimental policy mechanism in all active release lines:
    16.x, 18.x and, 20.x.
    Thank you, to LeoDog896 for reporting this vulnerability and thank you Tobias Nieen for fixing it.

    fs.statfs can retrive stats from files restricted by the Permission Model (LOW)(CVE-2023-32005)
    A vulnerability has been identified in Node.js version 20, affecting users of the experimental permission
    model when the --allow-fs-read flag is used with a non-* argument.

    This flaw arises from an inadequate permission model that fails to restrict file stats through the
    fs.statfs API. As a result, malicious actors can retrieve stats from files that they do not have explicit
    read access to.

    Please note that at the time this CVE was issued, the permission model is an experimental feature of
    Node.js.

    Impacts:

    This vulnerability affects all users using the experimental permission model in Node.js 20.
    Thank you to Rafael Gonzaga for reporting and fixing this vulnerability.

    fs.mkdtemp() and fs.mkdtempSync() are missing getValidatedPath() checks (LOW)(CVE-2023-32003)
    fs.mkdtemp() and fs.mkdtempSync() can be used to bypass the permission model check using a path traversal
    attack. This flaw arises from a missing check in the fs.mkdtemp() API and the impact is a malicious actor
    could create an arbitrary directory.

    Please note that at the time this CVE was issued, the permission model is an experimental feature of
    Node.js.

    Impacts:

    This vulnerability affects all users using the experimental permission model in Node.js 20.
    Thank you, to Axel Chong for reporting this vulnerability and thank you Rafael Gonzaga for fixing it.

    Downloads and release details
    Node.js v16.20.2 (LTS)
    Node.js v18.17.1 (LTS)
    Node.js v20.5.1 (Current)
    (Update 08-Aug-2023) Security Release target August 9th
    The Node.js Security Releases will be available on, or shortly after, Wednesday, August 9th, 2023.

    Summary
    The Node.js project will release new versions of the 16.x, 18.x and 20.x releases lines on or shortly
    after, Tuesday August 8th 2023 in order to address:

    3 high severity issues.
    2 medium severity issues.
    2 low severity issues.
    OpenSSL Security updates
    This security release includes the following OpenSSL security updates

    OpenSSL security advisory 14th July.
    OpenSSL security advisory 19th July.
    OpenSSL security advisory 31st July.
    Impact
    The 20.x release line of Node.js is vulnerable to 3 high severity issues, 2 medium severity issues, and 2
    low severity issues.

    The 18.x release line of Node.js is vulnerable to 1 high severity issue, and 2 medium severity issues.

    The 16.x release line of Node.js is vulnerable to 1 high severity issue, and 2 medium severity issues.

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-18476abd7e");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:nodejs16, 1:nodejs18 and / or 1:nodejs20 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-32002");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nodejs20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'nodejs16-16.20.2-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs18-18.17.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs20-20.5.1-1.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs16 / nodejs18 / nodejs20');
}
