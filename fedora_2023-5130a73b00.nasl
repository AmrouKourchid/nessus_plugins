#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-5130a73b00
#

include('compat.inc');

if (description)
{
  script_id(186628);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id("CVE-2023-47627");
  script_xref(name:"FEDORA", value:"2023-5130a73b00");

  script_name(english:"Fedora 39 : llhttp / python-aiohttp / uxplay (2023-5130a73b00)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-5130a73b00 advisory.

    Security fix for CVE-2023-47627

    https://pagure.io/fesco/issue/3106

    ## python-aiohttp 3.8.6 (2023-10-07)

    https://github.com/aio-libs/aiohttp/blob/v3.8.6/CHANGES.rst#386-2023-10-07

    ### Security bugfixes

    - Upgraded `llhttp` to v9.1.3: https://github.com/aio-libs/aiohttp/security/advisories/GHSA-pjjw-qhg8-p2p9
    - Updated Python parser to comply with RFCs 9110/9112: https://github.com/aio-
    libs/aiohttp/security/advisories/GHSA-gfw2-4jvh-wgfg

    ### Deprecation

    - Added `fallback_charset_resolver` parameter in `ClientSession` to allow a user-supplied character set
    detection function. Character set detection will no longer be included in 3.9 as a default. If this
    feature is needed, please use
    [`fallback_charset_resolver`](https://docs.aiohttp.org/en/stable/client_advanced.html#character-set-
    detection).

    ### Features

    - Enabled lenient response parsing for more flexible parsing in the client (this should resolve some
    regressions when dealing with badly formatted HTTP responses).

    ### Bugfixes

    - Fixed `PermissionError` when `.netrc` is unreadable due to permissions.
    - Fixed output of parsing errors pointing to a `\n`.
    - Fixed `GunicornWebWorker` max_requests_jitter not working.
    - Fixed sorting in `filter_cookies` to use cookie with longest path.
    - Fixed display of `BadStatusLine` messages from `llhttp`.

    ----

    ## llhttp 9.1.3

    ### Fixes

    - Restart the parser on HTTP 100
    - Fix chunk extensions quoted-string value parsing
    - Fix lenient_flags truncated on reset
    - Fix chunk extensions parameters parsing when more then one name-value pair provided

    ## llhttp 9.1.2

    ### What's Changed

    - Fix HTTP 1xx handling

    ## llhttp 9.1.1

    ### What's Changed

    - feat: Expose new lenient methods

    ## llhttp 9.1.0

    ### What's Changed

    - New lenient flag to make CR completely optional
    - New lenient flag to have spaces after chunk header

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-5130a73b00");
  script_set_attribute(attribute:"solution", value:
"Update the affected llhttp, python-aiohttp and / or uxplay packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-47627");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:llhttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:uxplay");
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
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'llhttp-9.1.3-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-aiohttp-3.8.6-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uxplay-1.66-2.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'llhttp / python-aiohttp / uxplay');
}
