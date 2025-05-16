#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-52154efd61
#

include('compat.inc');

if (description)
{
  script_id(169147);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2021-21408",
    "CVE-2021-26119",
    "CVE-2021-26120",
    "CVE-2021-29454",
    "CVE-2022-29221"
  );
  script_xref(name:"FEDORA", value:"2022-52154efd61");

  script_name(english:"Fedora 36 : php-Smarty (2022-52154efd61)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 36 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-52154efd61 advisory.

    ## [3.1.47] - 2022-09-14

    ### Security
    - Applied appropriate javascript and html escaping in mailto plugin to counter injection attacks
    [#454](https://github.com/smarty-php/smarty/issues/454)

    ### Fixed
    - Fixed use of `rand()` without a parameter in math function [#794](https://github.com/smarty-
    php/smarty/issues/794)
    - Fixed unselected year/month/day not working in html_select_date [#395](https://github.com/smarty-
    php/smarty/issues/395)

    ## [3.1.46] - 2022-08-01

    ### Fixed
    - Fixed problems with smarty_mb_str_replace [#549](https://github.com/smarty-php/smarty/issues/549)
    - Fixed second parameter of unescape modifier not working [#777](https://github.com/smarty-
    php/smarty/issues/777)

    ## [3.1.45] - 2022-05-17

    ### Security
    - Prevent PHP injection through malicious block name or include file name. This addresses CVE-2022-29221

    ### Fixed
    - Math equation `max(x, y)` didn't work anymore [#721](https://github.com/smarty-php/smarty/issues/721)

    ## [3.1.44] - 2022-01-18

    ### Fixed
    - Fixed illegal characters bug in math function security check [#702](https://github.com/smarty-
    php/smarty/issues/702)

    ## [3.1.43] - 2022-01-10

    ### Security
    - Prevent evasion of the `static_classes` security policy. This addresses CVE-2021-21408

    ## [3.1.42] - 2022-01-10

    ### Security
    - Prevent arbitrary PHP code execution through maliciously crafted expression for the math function. This
    addresses CVE-2021-29454

    ## [3.1.41] - 2022-01-09

    ### Security
    - Rewrote the mailto function to not use `eval` when encoding with javascript

    ## [3.1.40] - 2021-10-13

    ### Changed
    - modifier escape now triggers a E_USER_NOTICE when an unsupported escape type is used
    https://github.com/smarty-php/smarty/pull/649

    ### Security
    - More advanced javascript escaping to handle
    https://html.spec.whatwg.org/multipage/scripting.html#restrictions-for-contents-of-script-elements thanks
    to m-haritonov

    ## [3.1.39] - 2021-02-17

    ### Security
    - Prevent access to `$smarty.template_object` in sandbox mode. This addresses CVE-2021-26119.
    - Fixed code injection vulnerability by using illegal function names in `{function
    name='blah'}{/function}`. This addresses CVE-2021-26120.

    ## [3.1.38] - 2021-01-08

    ### Fixed
    - Smarty::SMARTY_VERSION wasn't updated https://github.com/smarty-php/smarty/issues/628

    ## [3.1.37] - 2021-01-07

    ### Changed
    - Changed error handlers and handling of undefined constants for php8-compatibility (set $errcontext
    argument optional) https://github.com/smarty-php/smarty/issues/605
    - Changed expected error levels in unit tests for php8-compatibility
    - Travis unit tests now run for all php versions >= 5.3, including php8
    - Travis runs on Xenial where possible

    ### Fixed
    - PHP5.3 compatibility fixes
    - Brought lexer source functionally up-to-date with compiled version

    ## [3.1.36] - 2020-04-14

    ### Fixed
     - Smarty::SMARTY_VERSION wasn't updated in v3.1.35 https://github.com/smarty-php/smarty/issues/584

    ## [3.1.35] - 2020-04-14
     - remove whitespaces after comments https://github.com/smarty-php/smarty/issues/447
     - fix foreachelse on arrayiterators https://github.com/smarty-php/smarty/issues/506
     - fix files contained in git export archive for package maintainers https://github.com/smarty-
    php/smarty/issues/325
     - throw SmartyException when setting caching attributes for cacheable plugin https://github.com/smarty-
    php/smarty/issues/457
     - fix errors that occured where isset was replaced with null check such as https://github.com/smarty-
    php/smarty/issues/453
     - unit tests are now in the repository

    ## 3.1.34 release - 05.11.2019
    13.01.2020
     - fix typo in exception message (JercSi)
     - fix typehint warning with callable (bets4breakfast)
     - add travis badge and compatability info to readme (matks)
     - fix stdClass cast when compiling foreach (carpii)
     - fix wrong set/get methods for memcached (IT-Experte)
     - fix pborm assigning value to object variables in smarty_internal_compile_assign (Hunman)
     - exclude error_reporting.ini from git export (glensc)

    ## 3.1.34-dev-6 -
    30.10.2018
     - bugfix a nested subblock in an inheritance child template was not replace by
       outer level block with same name in same child template https://github.com/smarty-php/smarty/issues/500

    29.10.2018
     - bugfix Smarty::$php_handling == PHP_PASSTHRU (default) did eat the \n (newline) character if it did
    directly followed
       a PHP tag like ?> or other https://github.com/smarty-php/smarty/issues/501

    14.10.2018
     - bugfix autoloader exit shortcut https://github.com/smarty-php/smarty/issues/467

    11.10.2018
     - bugfix {insert} not works when caching is enabled and included template is present
       https://github.com/smarty-php/smarty/issues/496
     - bugfix in date-format modifier; NULL at date string or default_date did not produce correct output
       https://github.com/smarty-php/smarty/pull/458

    09.10.2018
     - bugfix fix of 26.8.2017 https://github.com/smarty-php/smarty/issues/327
       modifier is applied to sum expression https://github.com/smarty-php/smarty/issues/491
     - bugfix indexed arrays could not be defined array(...)

    18.09.2018
      - bugfix large plain text template sections without a Smarty tag > 700kB could
        could fail in version 3.1.32 and 3.1.33 because PHP preg_match() restrictions
        https://github.com/smarty-php/smarty/issues/488

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-52154efd61");
  script_set_attribute(attribute:"solution", value:
"Update the affected php-Smarty package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26120");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:36");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-Smarty");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^36([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 36', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'php-Smarty-3.1.47-1.fc36', 'release':'FC36', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-Smarty');
}
