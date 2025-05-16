#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-973319d5b7
#

include('compat.inc');

if (description)
{
  script_id(173881);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2023-23918",
    "CVE-2023-23919",
    "CVE-2023-23920",
    "CVE-2023-23936",
    "CVE-2023-24807"
  );
  script_xref(name:"FEDORA", value:"2023-973319d5b7");

  script_name(english:"Fedora 38 : nodejs16 / nodejs18 / nodejs20 (2023-973319d5b7)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 38 host has packages installed that are affected by multiple vulnerabilities as referenced in the
FEDORA-2023-973319d5b7 advisory.

    Fixes for virtual Provides/Requires of `nodejs` and `nodejs-devel`

    ----

    Assorted fixes for v8-devel

    ----

    Update to 19.8.1

    Fix confilct with nodejs18


    ----

    ## 2023-02-16, Version 16.19.1 'Gallium' (LTS), @richardlau

    This is a security release.

    ### Notable Changes

    The following CVEs are fixed in this release:

    * **[CVE-2023-23918](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23918)**: Node.js Permissions
    policies can be bypassed via process.mainModule (High)
    * **[CVE-2023-23919](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23919)**: Node.js OpenSSL
    error handling issues in nodejs crypto library (Medium)
    * **[CVE-2023-23920](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23920)**: Node.js insecure
    loading of ICU data through ICU\_DATA environment variable (Low)

    Fixed by an update to undici:

    * **[CVE-2023-23936](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-23936)**: Fetch API in
    Node.js did not protect against CRLF injection in host headers (Medium)
      * See <https://github.com/nodejs/undici/security/advisories/GHSA-5r9g-qh6m-jxff> for more information.
    * **[CVE-2023-24807](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24807)**: Regular Expression
    Denial of Service in Headers in Node.js fetch API (Low)
      * See <https://github.com/nodejs/undici/security/advisories/GHSA-r6ch-mqf9-qc9w> for more information.

    More detailed information on each of the vulnerabilities can be found in [February 2023 Security
    Releases](https://nodejs.org/en/blog/vulnerability/february-2023-security-releases/) blog post.

    This security release includes OpenSSL security updates as outlined in the recent
    [OpenSSL security advisory](https://www.openssl.org/news/secadv/20230207.txt).

    ### Commits

    * \[[`7fef050447`](https://github.com/nodejs/node/commit/7fef050447)] - **build**: build ICU with
    ICU\_NO\_USER\_DATA\_OVERRIDE (RafaelGSS) [nodejs-private/node-private#374](https://github.com/nodejs-
    private/node-private/pull/374)
    * \[[`b558e9f476`](https://github.com/nodejs/node/commit/b558e9f476)] - **crypto**: clear OpenSSL error on
    invalid ca cert (RafaelGSS) [nodejs-private/node-private#375](https://github.com/nodejs-private/node-
    private/pull/375)
    * \[[`160adb7ffc`](https://github.com/nodejs/node/commit/160adb7ffc)] - **crypto**: clear OpenSSL error
    queue after calling X509\_check\_private\_key() (Filip Skokan)
    [#45495](https://github.com/nodejs/node/pull/45495)
    * \[[`d0ece30948`](https://github.com/nodejs/node/commit/d0ece30948)] - **crypto**: clear OpenSSL error
    queue after calling X509\_verify() (Takuro Sato) [#45377](https://github.com/nodejs/node/pull/45377)
    * \[[`2d9ae4f184`](https://github.com/nodejs/node/commit/2d9ae4f184)] - **deps**: update undici to v5.19.1
    (Matteo Collina) [nodejs-private/node-private#388](https://github.com/nodejs-private/node-
    private/pull/388)
    * \[[`d80e8312fd`](https://github.com/nodejs/node/commit/d80e8312fd)] - **deps**: cherry-pick Windows
    ARM64 fix for openssl (Richard Lau) [#46568](https://github.com/nodejs/node/pull/46568)
    * \[[`de5c8d2c2f`](https://github.com/nodejs/node/commit/de5c8d2c2f)] - **deps**: update archs files for
    quictls/openssl-1.1.1t+quic (RafaelGSS) [#46568](https://github.com/nodejs/node/pull/46568)
    * \[[`1a8ccfe908`](https://github.com/nodejs/node/commit/1a8ccfe908)] - **deps**: upgrade openssl sources
    to OpenSSL\_1\_1\_1t+quic (RafaelGSS) [#46568](https://github.com/nodejs/node/pull/46568)
    * \[[`693789780b`](https://github.com/nodejs/node/commit/693789780b)] - **doc**: clarify release notes for
    Node.js 16.19.0 (Richard Lau) [#45846](https://github.com/nodejs/node/pull/45846)
    * \[[`f95ef064f4`](https://github.com/nodejs/node/commit/f95ef064f4)] - **lib**: makeRequireFunction patch
    when experimental policy (RafaelGSS) [nodejs-private/node-private#358](https://github.com/nodejs-
    private/node-private/pull/358)
    * \[[`b02d895137`](https://github.com/nodejs/node/commit/b02d895137)] - **policy**: makeRequireFunction on
    mainModule.require (RafaelGSS) [nodejs-private/node-private#358](https://github.com/nodejs-private/node-
    private/pull/358)
    * \[[`d7f83c420c`](https://github.com/nodejs/node/commit/d7f83c420c)] - **test**: avoid left behind child
    processes (Richard Lau) [#46276](https://github.com/nodejs/node/pull/46276)

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-973319d5b7");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:nodejs16, 1:nodejs18 and / or 1:nodejs20 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23918");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:38");
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
if (! preg(pattern:"^38([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 38', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'nodejs16-16.20.0-2.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs18-18.15.0-6.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'nodejs20-19.8.1-7.fc38', 'release':'FC38', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
