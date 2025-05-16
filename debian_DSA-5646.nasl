#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5646. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(192517);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_cve_id(
    "CVE-2023-39360",
    "CVE-2023-39513",
    "CVE-2023-49084",
    "CVE-2023-49085",
    "CVE-2023-49086",
    "CVE-2023-49088",
    "CVE-2023-50250",
    "CVE-2023-50569"
  );

  script_name(english:"Debian dsa-5646 : cacti - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 / 12 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dsa-5646 advisory.

  - Cacti is an open source operational monitoring and fault management framework.Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability allows an authenticated user to poison data.
    The vulnerability is found in `graphs_new.php`. Several validations are performed, but the `returnto`
    parameter is directly passed to `form_save_button`. In order to bypass this validation, returnto must
    contain `host.php`. This vulnerability has been addressed in version 1.2.25. Users are advised to upgrade.
    Users unable to update should manually filter HTML output. (CVE-2023-39360)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability which allows an authenticated user to poison
    data stored in the _cacti_'s database. These data will be viewed by administrative _cacti_ accounts and
    execute JavaScript code in the victim's browser at view-time. The script under `host.php` is used to
    monitor and manage hosts in the _cacti_ app, hence displays useful information such as data queries and
    verbose logs. _CENSUS_ found that an adversary that is able to configure a data-query template with
    malicious code appended in the template path, in order to deploy a stored XSS attack against any user with
    the _General Administration>Sites/Devices/Data_ privileges. A user that possesses the _Template
    Editor>Data Queries_ permissions can configure the data query template path in _cacti_. Please note that
    such a user may be a low privileged user. This configuration occurs through
    `http://<HOST>/cacti/data_queries.php` by editing an existing or adding a new data query template. If a
    template is linked to a device then the formatted template path will be rendered in the device's
    management page, when a _verbose data query_ is requested. This vulnerability has been addressed in
    version 1.2.25. Users are advised to upgrade. Users unable to update should manually filter HTML output.
    (CVE-2023-39513)

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

  - Reflected Cross Site Scripting (XSS) vulnerability in Cacti v1.2.25, allows remote attackers to escalate
    privileges when uploading an xml template file via templates_import.php. (CVE-2023-50569)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/cacti");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39360");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-39513");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49084");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49086");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-49088");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50250");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-50569");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/cacti");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/cacti");
  script_set_attribute(attribute:"solution", value:
"Upgrade the cacti packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-49085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti RCE via SQLi in pollers.php');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
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
if (! preg(pattern:"^(11)\.[0-9]+|^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0 / 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'cacti', 'reference': '1.2.16+ds1-2+deb11u3'},
    {'release': '12.0', 'prefix': 'cacti', 'reference': '1.2.24+ds1-1+deb12u2'}
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
