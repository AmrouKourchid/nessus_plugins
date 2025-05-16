#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0275-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(181918);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/27");

  script_cve_id(
    "CVE-2023-30534",
    "CVE-2023-39357",
    "CVE-2023-39358",
    "CVE-2023-39359",
    "CVE-2023-39360",
    "CVE-2023-39361",
    "CVE-2023-39362",
    "CVE-2023-39364",
    "CVE-2023-39365",
    "CVE-2023-39366",
    "CVE-2023-39510",
    "CVE-2023-39511",
    "CVE-2023-39512",
    "CVE-2023-39513",
    "CVE-2023-39514",
    "CVE-2023-39515",
    "CVE-2023-39516"
  );

  script_name(english:"openSUSE 15 Security Update : cacti, cacti-spine (openSUSE-SU-2023:0275-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
openSUSE-SU-2023:0275-1 advisory.

  - Cacti is an open source operational monitoring and fault management framework. There are two instances of
    insecure deserialization in Cacti version 1.2.24. While a viable gadget chain exists in Cacti's vendor
    directory (phpseclib), the necessary gadgets are not included, making them inaccessible and the insecure
    deserializations not exploitable. Each instance of insecure deserialization is due to using the
    unserialize function without sanitizing the user input. Cacti has a safe deserialization that attempts
    to sanitize the content and check for specific values before calling unserialize, but it isn't used in
    these instances. The vulnerable code lies in graphs_new.php, specifically within the host_new_graphs_save
    function. This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are no
    known workarounds for this vulnerability. (CVE-2023-30534)

  - Cacti is an open source operational monitoring and fault management framework. A defect in the sql_save
    function was discovered. When the column type is numeric, the sql_save function directly utilizes user
    input. Many files and functions calling the sql_save function do not perform prior validation of user
    input, leading to the existence of multiple SQL injection vulnerabilities in Cacti. This allows
    authenticated users to exploit these SQL injection vulnerabilities to perform privilege escalation and
    remote code execution. This issue has been addressed in version 1.2.25. Users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2023-39357)

  - Cacti is an open source operational monitoring and fault management framework. An authenticated SQL
    injection vulnerability was discovered which allows authenticated users to perform privilege escalation
    and remote code execution. The vulnerability resides in the `reports_user.php` file. In
    `ajax_get_branches`, the `tree_id` parameter is passed to the `reports_get_branch_select` function without
    any validation. This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are
    no known workarounds for this vulnerability. (CVE-2023-39358)

  - Cacti is an open source operational monitoring and fault management framework. An authenticated SQL
    injection vulnerability was discovered which allows authenticated users to perform privilege escalation
    and remote code execution. The vulnerability resides in the `graphs.php` file. When dealing with the cases
    of ajax_hosts and ajax_hosts_noany, if the `site_id` parameter is greater than 0, it is directly reflected
    in the WHERE clause of the SQL statement. This creates an SQL injection vulnerability. This issue has been
    addressed in version 1.2.25. Users are advised to upgrade. There are no known workarounds for this
    vulnerability. (CVE-2023-39359)

  - Cacti is an open source operational monitoring and fault management framework.Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability allows an authenticated user to poison data.
    The vulnerability is found in `graphs_new.php`. Several validations are performed, but the `returnto`
    parameter is directly passed to `form_save_button`. In order to bypass this validation, returnto must
    contain `host.php`. This vulnerability has been addressed in version 1.2.25. Users are advised to upgrade.
    Users unable to update should manually filter HTML output. (CVE-2023-39360)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a SQL injection discovered in graph_view.php. Since guest users can access graph_view.php
    without authentication by default, if guest users are being utilized in an enabled state, there could be
    the potential for significant damage. Attackers may exploit this vulnerability, and there may be
    possibilities for actions such as the usurpation of administrative privileges or remote code execution.
    This issue has been addressed in version 1.2.25. Users are advised to upgrade. There are no known
    workarounds for this vulnerability. (CVE-2023-39361)

  - Cacti is an open source operational monitoring and fault management framework. In Cacti 1.2.24, under
    certain conditions, an authenticated privileged user, can use a malicious string in the SNMP options of a
    Device, performing command injection and obtaining remote code execution on the underlying server. The
    `lib/snmp.php` file has a set of functions, with similar behavior, that accept in input some variables and
    place them into an `exec` call without a proper escape or validation. This issue has been addressed in
    version 1.2.25. Users are advised to upgrade. There are no known workarounds for this vulnerability.
    (CVE-2023-39362)

  - Cacti is an open source operational monitoring and fault management framework. In Cacti 1.2.24, users with
    console access can be redirected to an arbitrary website after a change password performed via a
    specifically crafted URL. The `auth_changepassword.php` file accepts `ref` as a URL parameter and reflects
    it in the form used to perform the change password. It's value is used to perform a redirect via `header`
    PHP function. A user can be tricked in performing the change password operation, e.g., via a phishing
    message, and then interacting with the malicious website where the redirection has been performed, e.g.,
    downloading malwares, providing credentials, etc. This issue has been addressed in version 1.2.25. Users
    are advised to upgrade. There are no known workarounds for this vulnerability. (CVE-2023-39364)

  - Cacti is an open source operational monitoring and fault management framework. Issues with Cacti Regular
    Expression validation combined with the external links feature can lead to limited SQL Injections and
    subsequent data leakage. This issue has been addressed in version 1.2.25. Users are advised to upgrade.
    There are no known workarounds for this vulnerability. (CVE-2023-39365)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability allows an authenticated user to poison data
    stored in the _cacti_'s database. These data will be viewed by administrative _cacti_ accounts and execute
    JavaScript code in the victim's browser at view-time. The `data_sources.php` script displays the data
    source management information (e.g. data source path, polling configuration etc.) for different data
    visualizations of the _cacti_ app. CENSUS found that an adversary that is able to configure a malicious
    Device name, can deploy a stored XSS attack against any user of the same (or broader) privileges. A user
    that possesses the _General Administration>Sites/Devices/Data_ permissions can configure the device names
    in _cacti_. This configuration occurs through `http://<HOST>/cacti/host.php`, while the rendered malicious
    payload is exhibited at `http://<HOST>/cacti/data_sources.php`. This vulnerability has been addressed in
    version 1.2.25. Users are advised to upgrade. Users unable to update should manually filter HTML output.
    (CVE-2023-39366)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability allows an authenticated user to poison data
    stored in the _cacti_'s database. These data will be viewed by administrative _cacti_ accounts and execute
    JavaScript code in the victim's browser at view-time. The`reports_admin.php` script displays reporting
    information about graphs, devices, data sources etc. CENSUS found that an adversary that is able to
    configure a malicious Device name, can deploy a stored XSS attack against any user of the same (or
    broader) privileges. A user that possesses the _General Administration>Sites/Devices/Data_ permissions can
    configure the device names in _cacti_. This configuration occurs through `http://<HOST>/cacti/host.php`,
    while the rendered malicious payload is exhibited at `http://<HOST>/cacti/reports_admin.php` when the a
    graph with the maliciously altered device name is linked to the report. This vulnerability has been
    addressed in version 1.2.25. Users are advised to upgrade. Users unable to update should manually filter
    HTML output. (CVE-2023-39510)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability which allows an authenticated user to poison
    data stored in the _cacti_'s database. These data will be viewed by administrative _cacti_ accounts and
    execute JavaScript code in the victim's browser at view-time. The script under `reports_admin.php`
    displays reporting information about graphs, devices, data sources etc. _CENSUS_ found that an adversary
    that is able to configure a malicious device name, related to a graph attached to a report, can deploy a
    stored XSS attack against any super user who has privileges of viewing the `reports_admin.php` page, such
    as administrative accounts. A user that possesses the _General Administration>Sites/Devices/Data_
    permissions can configure the device names in _cacti_. This configuration occurs through
    `http://<HOST>/cacti/host.php`, while the rendered malicious payload is exhibited at
    `http://<HOST>/cacti/reports_admin.php` when the a graph with the maliciously altered device name is
    linked to the report. This issue has been addressed in version 1.2.25. Users are advised to upgrade. Users
    unable to upgrade should manually filter HTML output. (CVE-2023-39511)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability which allows an authenticated user to poison
    data stored in the _cacti_'s database. These data will be viewed by administrative _cacti_ accounts and
    execute JavaScript code in the victim's browser at view-time. The script under `data_sources.php` displays
    the data source management information (e.g. data source path, polling configuration, device name related
    to the datasource etc.) for different data visualizations of the _cacti_ app. _CENSUS_ found that an
    adversary that is able to configure a malicious device name, can deploy a stored XSS attack against any
    user of the same (or broader) privileges. A user that possesses the _General
    Administration>Sites/Devices/Data_ permissions can configure the device names in _cacti_. This
    configuration occurs through `http://<HOST>/cacti/host.php`, while the rendered malicious payload is
    exhibited at `http://<HOST>/cacti/data_sources.php`. This vulnerability has been addressed in version
    1.2.25. Users are advised to upgrade. Users unable to update should manually filter HTML output.
    (CVE-2023-39512)

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

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability which allows an authenticated user to poison
    data stored in the _cacti_'s database. These data will be viewed by administrative _cacti_ accounts and
    execute JavaScript code in the victim's browser at view-time. The script under `graphs.php` displays graph
    details such as data-source paths, data template information and graph related fields. _CENSUS_ found that
    an adversary that is able to configure either a data-source template with malicious code appended in the
    data-source name or a device with a malicious payload injected in the device name, may deploy a stored XSS
    attack against any user with _General Administration>Graphs_ privileges. A user that possesses the
    _Template Editor>Data Templates_ permissions can configure the data-source name in _cacti_. Please note
    that this may be a _low privileged_ user. This configuration occurs through
    `http://<HOST>/cacti/data_templates.php` by editing an existing or adding a new data template. If a
    template is linked to a graph then the formatted template name will be rendered in the graph's management
    page. A user that possesses the _General Administration>Sites/Devices/Data_ permissions can configure the
    device name in _cacti_. This vulnerability has been addressed in version 1.2.25. Users are advised to
    upgrade. Users unable to upgrade should add manual HTML escaping. (CVE-2023-39514)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability allows an authenticated user to poison data
    stored in the cacti's database. These data will be viewed by administrative cacti accounts and execute
    JavaScript code in the victim's browser at view-time. The script under `data_debug.php` displays data
    source related debugging information such as _data source paths, polling settings, meta-data on the data
    source_. _CENSUS_ found that an adversary that is able to configure a malicious data-source path, can
    deploy a stored XSS attack against any user that has privileges related to viewing the `data_debug.php`
    information. A user that possesses the _General Administration>Sites/Devices/Data_ permissions can
    configure the data source path in _cacti_. This configuration occurs through
    `http://<HOST>/cacti/data_sources.php`. This vulnerability has been addressed in version 1.2.25. Users are
    advised to upgrade. Users unable to update should manually filter HTML output. (CVE-2023-39515)

  - Cacti is an open source operational monitoring and fault management framework. Affected versions are
    subject to a Stored Cross-Site-Scripting (XSS) Vulnerability which allows an authenticated user to poison
    data stored in the _cacti_'s database. These data will be viewed by administrative _cacti_ accounts and
    execute JavaScript code in the victim's browser at view-time. The script under `data_sources.php` displays
    the data source management information (e.g. data source path, polling configuration etc.) for different
    data visualizations of the _cacti_ app. CENSUS found that an adversary that is able to configure a
    malicious data-source path, can deploy a stored XSS attack against any user of the same (or broader)
    privileges. A user that possesses the 'General Administration>Sites/Devices/Data' permissions can
    configure the data source path in Cacti. This configuration occurs through
    `http://<HOST>/cacti/data_sources.php`. The same page can be used for previewing the data source path.
    This issue has been addressed in version 1.2.25. Users are advised to upgrade. Users unable to upgrade
    should manually escape HTML output. (CVE-2023-39516)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215040");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215043");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215047");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215050");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215051");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215052");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215055");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215056");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215059");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215081");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215082");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JFJCU2NOOFCO7XJZOUW2BQ6HWJMHSYSN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e5c32ce1");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-30534");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39357");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39358");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39359");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39360");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39361");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39362");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39364");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39365");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39366");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39510");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39511");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39512");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39513");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39514");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39515");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39516");
  script_set_attribute(attribute:"solution", value:
"Update the affected cacti and / or cacti-spine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39361");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
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
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4|SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4 / 15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'cacti-1.2.25-bp155.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cacti-1.2.25-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cacti-spine-1.2.25-bp155.2.3.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cacti-spine-1.2.25-bp155.2.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
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
