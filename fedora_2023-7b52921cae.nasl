#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2023-7b52921cae
#

include('compat.inc');

if (description)
{
  script_id(185303);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2023-38552",
    "CVE-2023-39331",
    "CVE-2023-39332",
    "CVE-2023-39333",
    "CVE-2023-44487",
    "CVE-2023-45143"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"FEDORA", value:"2023-7b52921cae");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Fedora 39 : nodejs20 (2023-7b52921cae)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 39 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2023-7b52921cae advisory.

    ## 2023-10-13, Version 20.8.1 (Current), @RafaelGSS

    This is a security release.

    ### Notable Changes

    The following CVEs are fixed in this release:

    * [CVE-2023-44487](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-44487): `nghttp2` Security
    Release (High)
    * [CVE-2023-45143](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45143): `undici` Security
    Release (High)
    * [CVE-2023-39332](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39332): Path traversal through
    path stored in Uint8Array (High)
    * [CVE-2023-39331](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39331): Permission model
    improperly protects against path traversal (High)
    * [CVE-2023-38552](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38552):  Integrity checks
    according to policies can be circumvented (Medium)
    * [CVE-2023-39333](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-39333): Code injection via
    WebAssembly export names (Low)

    More detailed information on each of the vulnerabilities can be found in [October 2023 Security
    Releases](https://nodejs.org/en/blog/vulnerability/october-2023-security-releases/) blog post.

    ----

    ## 2023-09-28, Version 20.8.0 (Current), @ruyadorno

    ### Notable Changes

    #### Stream performance improvements

    Performance improvements to writable and readable streams, improving the creation and destruction by 15%
    and reducing the memory overhead each stream takes in Node.js

    Contributed by Benjamin Gruenbaum in [#49745](https://github.com/nodejs/node/pull/49745) and Raz Luvaton
    in [#49834](https://github.com/nodejs/node/pull/49834).

    Performance improvements for readable webstream, improving readable stream async iterator consumption by
    140% and improving readable stream `pipeTo` consumption by 60%

    Contributed by Raz Luvaton in [#49662](https://github.com/nodejs/node/pull/49662) and
    [#49690](https://github.com/nodejs/node/pull/49690).

    #### Rework of memory management in `vm` APIs with the `importModuleDynamically` option

    This rework addressed a series of long-standing memory leaks and use-after-free issues in the following
    APIs that support `importModuleDynamically`:

    * `vm.Script`
    * `vm.compileFunction`
    * `vm.SyntheticModule`
    * `vm.SourceTextModule`

    This should enable affected users (in particular Jest users) to upgrade from older versions of Node.js.

    Contributed by Joyee Cheung in [#48510](https://github.com/nodejs/node/pull/48510).

    #### Other notable changes

    * \[[`32d4d29d02`](https://github.com/nodejs/node/commit/32d4d29d02)] - **deps**: add
    v8::Object::SetInternalFieldForNodeCore() (Joyee Cheung)
    [#49874](https://github.com/nodejs/node/pull/49874)
    * \[[`0e686d096b`](https://github.com/nodejs/node/commit/0e686d096b)] - **doc**: deprecate `fs.F_OK`,
    `fs.R_OK`, `fs.W_OK`, `fs.X_OK` (Livia Medeiros) [#49683](https://github.com/nodejs/node/pull/49683)
    * \[[`a5dd057540`](https://github.com/nodejs/node/commit/a5dd057540)] - **doc**: deprecate
    `util.toUSVString` (Yagiz Nizipli) [#49725](https://github.com/nodejs/node/pull/49725)
    * \[[`7b6a73172f`](https://github.com/nodejs/node/commit/7b6a73172f)] - **doc**: deprecate calling
    `promisify` on a function that returns a promise (Antoine du Hamel)
    [#49647](https://github.com/nodejs/node/pull/49647)
    * \[[`1beefd5f16`](https://github.com/nodejs/node/commit/1beefd5f16)] - **esm**: set all hooks as release
    candidate (Geoffrey Booth) [#49597](https://github.com/nodejs/node/pull/49597)
    * \[[`b0ce78a75b`](https://github.com/nodejs/node/commit/b0ce78a75b)] - **module**: fix the leak in
    SourceTextModule and ContextifySript (Joyee Cheung) [#48510](https://github.com/nodejs/node/pull/48510)
    * \[[`4e578f8ab1`](https://github.com/nodejs/node/commit/4e578f8ab1)] - **module**: fix leak of
    vm.SyntheticModule (Joyee Cheung) [#48510](https://github.com/nodejs/node/pull/48510)
    * \[[`69e4218772`](https://github.com/nodejs/node/commit/69e4218772)] - **module**: use symbol in WeakMap
    to manage host defined options (Joyee Cheung) [#48510](https://github.com/nodejs/node/pull/48510)
    * \[[`14ece0aa76`](https://github.com/nodejs/node/commit/14ece0aa76)] - **(SEMVER-MINOR)** **src**: allow
    embedders to override NODE\_MODULE\_VERSION (Cheng Zhao)
    [#49279](https://github.com/nodejs/node/pull/49279)
    * \[[`9fd67fbff0`](https://github.com/nodejs/node/commit/9fd67fbff0)] - **stream**: use bitmap in writable
    state (Raz Luvaton) [#49834](https://github.com/nodejs/node/pull/49834)
    * \[[`0ccd4638ac`](https://github.com/nodejs/node/commit/0ccd4638ac)] - **stream**: use bitmap in readable
    state (Benjamin Gruenbaum) [#49745](https://github.com/nodejs/node/pull/49745)
    * \[[`7c5e322346`](https://github.com/nodejs/node/commit/7c5e322346)] - **stream**: improve webstream
    readable async iterator performance (Raz Luvaton) [#49662](https://github.com/nodejs/node/pull/49662)
    * \[[`80b342cc38`](https://github.com/nodejs/node/commit/80b342cc38)] - **(SEMVER-MINOR)**
    **test\_runner**: accept `testOnly` in `run` (Moshe Atlow)
    [#49753](https://github.com/nodejs/node/pull/49753)
    * \[[`17a05b141d`](https://github.com/nodejs/node/commit/17a05b141d)] - **(SEMVER-MINOR)**
    **test\_runner**: add junit reporter (Moshe Atlow) [#49614](https://github.com/nodejs/node/pull/49614)

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-7b52921cae");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:nodejs20 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39332");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:39");
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
if (! preg(pattern:"^39([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 39', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'nodejs20-20.8.1-1.fc39', 'release':'FC39', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'nodejs20');
}
