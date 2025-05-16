#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3884. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(206807);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/20");

  script_cve_id(
    "CVE-2022-41444",
    "CVE-2024-25641",
    "CVE-2024-31443",
    "CVE-2024-31444",
    "CVE-2024-31445",
    "CVE-2024-31458",
    "CVE-2024-31459",
    "CVE-2024-31460",
    "CVE-2024-34340"
  );

  script_name(english:"Debian dla-3884 : cacti - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3884 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3884-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    September 09, 2024                            https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : cacti
    Version        : 1.2.16+ds1-2+deb11u4
    CVE ID         : CVE-2022-41444 CVE-2024-25641 CVE-2024-31443 CVE-2024-31444
                     CVE-2024-31445 CVE-2024-31458 CVE-2024-31459 CVE-2024-31460
                     CVE-2024-34340

    Cacti, a web interface for graphing of monitoring systems, was vulnerable.

    CVE-2022-41444

        A Cross Site Scripting (XSS) vulnerability was found via crafted
        POST request to graphs_new.php.

    CVE-2024-25641

        An arbitrary file write vulnerability was found, exploitable through
        the Package Import feature. This vulnerability allowed authenticated
        users having the Import Templates permission to execute
        arbitrary PHP code (RCE) on the web server.

    CVE-2024-31443

        A Cross Site Scripting (XSS) vulnerabilty was found via crafted request
        to data_queries.php file.

    CVE-2024-31444

        A Cross Site Scripting (XSS) vulnerabilty was found via crafted request
        to automation_tree_rules.php file, via automation_tree_rules_form_save()
        function.

    CVE-2024-31445

        A SQL injection vulnerabilty was found in automation_get_new_graphs_sql
        function of `api_automation.php` allows authenticated users to exploit
        these SQL injection vulnerabilities to perform privilege escalation and
        remote code execution.

    CVE-2024-31458

        A SQL injection vulnerability was found in form_save() function in
        graph_template_inputs.php file.

    CVE-2024-31459

        A file inclusion issue in the 'lib/plugin.php' file was found. Combined
        with a SQL injection vulnerabilities, remote code execution (RCE) can
        be implemented.

    CVE-2024-31460

        A SQL injection vulnerability was found in some of the data stored in
        automation_tree_rules.php file.

    CVE-2024-34340

        A type juggling vulnerability was found in compat_password_verify function.
        Md5-hashed user input is compared with correct password in database by
        `$md5 == $hash`.
        It is a loose comparison, not the correct stricter `===`.

    For Debian 11 bullseye, these problems have been fixed in version
    1.2.16+ds1-2+deb11u4.

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
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-41444");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-25641");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31444");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31445");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31459");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31460");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-34340");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/cacti");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cacti packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-34340");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti Import Packages RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'cacti', 'reference': '1.2.16+ds1-2+deb11u4'}
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
