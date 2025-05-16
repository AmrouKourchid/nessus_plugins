#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3765. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192197);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id(
    "CVE-2023-39357",
    "CVE-2023-39360",
    "CVE-2023-39361",
    "CVE-2023-39362",
    "CVE-2023-39364",
    "CVE-2023-39365",
    "CVE-2023-39513",
    "CVE-2023-39515",
    "CVE-2023-39516",
    "CVE-2023-49084",
    "CVE-2023-49085",
    "CVE-2023-49086",
    "CVE-2023-49088"
  );

  script_name(english:"Debian dla-3765 : cacti - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3765 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3765-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Sylvain Beucler
    March 18, 2024                                https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : cacti
    Version        : 1.2.2+ds1-2+deb10u6
    CVE ID         : CVE-2023-39357 CVE-2023-39360 CVE-2023-39361 CVE-2023-39362
                     CVE-2023-39364 CVE-2023-39365 CVE-2023-39513 CVE-2023-39515
                     CVE-2023-39516 CVE-2023-49084 CVE-2023-49085 CVE-2023-49086
                     CVE-2023-49088
    Debian Bug     : 1059254

    Multiple vulnerabilities were found in Cacti, a network monitoring
    system. An attacker could manipulate the database, execute code
    remotely, launch DoS (denial-of-service) attacks or impersonate Cacti
    users, in some situations.

    CVE-2023-39357

        When the column type is numeric, the sql_save function directly
        utilizes user input. Many files and functions calling the sql_save
        function do not perform prior validation of user input, leading to
        the existence of multiple SQL injection vulnerabilities in
        Cacti. This allows authenticated users to exploit these SQL
        injection vulnerabilities to perform privilege escalation and
        remote code execution.

    CVE-2023-39360

        Stored Cross-Site-Scripting (XSS) Vulnerability allows an
        authenticated user to poison data. The vulnerability is found in
        `graphs_new.php`. Several validations are performed, but the
        `returnto` parameter is directly passed to `form_save_button`. In
        order to bypass this validation, returnto must contain `host.php`.

    CVE-2023-39361

        SQL injection discovered in graph_view.php. Since guest users can
        access graph_view.php without authentication by default, if guest
        users are being utilized in an enabled state, there could be the
        potential for significant damage. Attackers may exploit this
        vulnerability, and there may be povssibilities for actions such as
        the usurpation of administrative privileges or remote code
        execution.

    CVE-2023-39362

        An authenticated privileged user, can use a malicious string in
        the SNMP options of a Device, performing command injection and
        obtaining remote code execution on the underlying server. The
        `lib/snmp.php` file has a set of functions, with similar behavior,
        that accept in input some variables and place them into an `exec`
        call without a proper escape or validation.

    CVE-2023-39364

        Users with console access can be redirected to an arbitrary
        website after a change password performed via a specifically
        crafted URL. The `auth_changepassword.php` file accepts `ref` as a
        URL parameter and reflects it in the form used to perform the
        change password. It's value is used to perform a redirect via
        `header` PHP function. A user can be tricked in performing the
        change password operation, e.g., via a phishing message, and then
        interacting with the malicious website where the redirection has
        been performed, e.g., downloading malwares, providing credentials,
        etc.

    CVE-2023-39365

        Issues with Cacti Regular Expression validation combined with the
        external links feature can lead to limited SQL Injections and
        subsequent data leakage.

    CVE-2023-39513

        Stored Cross-Site-Scripting (XSS) Vulnerability which allows an
        authenticated user to poison data stored in the _cacti_'s
        database. The script under `host.php` is used to monitor and
        manage hosts in the _cacti_ app, hence displays useful information
        such as data queries and verbose logs.

    CVE-2023-39515

        Stored Cross-Site-Scripting (XSS) Vulnerability allows an
        authenticated user to poison data stored in the cacti's
        database. These data will be viewed by administrative cacti
        accounts and execute JavaScript code in the victim's browser at
        view-time. The script under `data_debug.php` displays data source
        related debugging information such as _data source paths, polling
        settings, meta-data on the data source.

    CVE-2023-39516

        Stored Cross-Site-Scripting (XSS) Vulnerability which allows an
        authenticated user to poison data stored in the _cacti_'s
        database. These data will be viewed by administrative _cacti_
        accounts and execute JavaScript code in the victim's browser at
        view-time. The script under `data_sources.php` displays the data
        source management information (e.g. data source path, polling
        configuration etc.) for different data visualizations of the
        _cacti_ app.

    CVE-2023-49084

        While using the detected SQL Injection and insufficient processing
        of the include file path, it is possible to execute arbitrary code
        on the server. Exploitation of the vulnerability is possible for
        an authorized user. The vulnerable component is the `link.php`.

    CVE-2023-49085

        It is possible to execute arbitrary SQL code through the
        `pollers.php` script. An authorized user may be able to execute
        arbitrary SQL code. The vulnerable component is the `pollers.php`.

    CVE-2023-49086

        Bypassing an earlier fix (CVE-2023-39360) that leads to a DOM XSS
        attack. Exploitation of the vulnerability is possible for an
        authorized user. The vulnerable component is the `graphs_new.php`.

    CVE-2023-49088

        The fix applied for CVE-2023-39515 in version 1.2.25 is incomplete
        as it enables an adversary to have a victim browser execute
        malicious code when a victim user hovers their mouse over the
        malicious data source path in `data_debug.php`.

    For Debian 10 buster, these problems have been fixed in version
    1.2.2+ds1-2+deb10u6.

    We recommend that you upgrade your cacti packages.

    For the detailed security status of cacti please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/cacti

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cacti");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39357");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39360");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39361");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39362");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39364");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39365");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39513");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39515");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39516");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49086");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49088");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/cacti");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cacti packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39361");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti RCE via SQLi in pollers.php');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'cacti', 'reference': '1.2.2+ds1-2+deb10u6'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cacti');
}
