#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-1635.
##

include('compat.inc');

if (description)
{
  script_id(181104);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2013-0281");

  script_name(english:"Oracle Linux 6 : pacemaker (ELSA-2013-1635)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2013-1635 advisory.

    [1.1.10-14]
    - Log: crmd: Supply arguments in the correct order
        Resolves: rhbz#996850
    - Fix: Invalid formatting of log message causes crash
        Resolves: rhbz#996850

    [1.1.10-13]
    - Fix: cman: Start clvmd and friends from the init script if enabled

    [1.1.10-12]
    - Fix: Consistently use 'Slave' as the role for unpromoted master/slave resources
        Resolves: rhbz#1011618
    - Fix: pengine: Location constraints with role=Started should prevent masters from running at all
        Resolves: rhbz#902407
    - Fix: crm_resource: Observe --master modifier for --move
        Resolves: rhbz#902407

    [1.1.10-11]
    + Fix: cman: Do not start pacemaker if cman startup fails
      + Fix: Fencing: Observe pcmk_host_list during automatic unfencing
        Resolves: rhbz#996850

    [1.1.10-10]
    - Remove unsupported resource agent
        Resolves: rhbz#1005678
    - Provide a meaningful error if --master is used for primitives and groups

    [1.1.10-9]
    + Fix: xml: Location constraints are allowed to specify a role
      + Bug rhbz#902407 - crm_resource: Handle --ban for master/slave resources as advertised
        Resolves: rhbz#902407

    [1.1.10-8]
    + Fix: mcp: Remove LSB hints that instruct chkconfig to start pacemaker at boot time
        Resolves: rhbz#997346

    [1.1.10-7]
    + Fencing: Support agents that need the host to be unfenced at startup
        Resolves: rhbz#996850
      + Fix: crm_report: Collect corosync quorum data
        Resolves: rhbz#989292

    [1.1.10-6]
    - Regenerate patches to have meaningful names

    [1.1.10-5]
    + Fix: systemd: Prevent glib assertion - only call g_error_free with non-NULL arguments
      + Fix: systemd: Prevent additional use-of-NULL assertions in g_error_free
      + Fix: logging: glib CRIT messages should not produce core files in the background
      + Fix: crmd: Correcty update the history cache when recurring ops change their return code
      + Log: crm_mon: Unmangle the output for failed operations
      + Log: cib: Correctly log short-form xml diffs
      + Log: pengine: Better indicate when a resource has failed

    [1.1.10-4]
    + Fix: crmd: Prevent crash by passing log arguments in the correct order
      + Fix: pengine: Do not re-allocate clone instances that are blocked in the Stopped state
      + Fix: pengine: Do not allow colocation with blocked clone instances

    [1.1.10-3]
    + Fix: pengine: Do not restart resources that depend on unmanaged resources
      + Fix: crmd: Prevent recurring monitors being cancelled due to notify operations

    [1.1.10-2]
    - Drop rgmanager 'provides' directive

    [1.1.10-1]
    - Update source tarball to revision: Pacemaker-1.1.10
    - See included ChangeLog file or https://raw.github.com/ClusterLabs/pacemaker/master/ChangeLog for full
    details

    - Resolves: rhbz#891766
    - Resolves: rhbz#902407
    - Resolves: rhbz#908450
    - Resolves: rhbz#913093
    - Resolves: rhbz#951340
    - Resolves: rhbz#951371
    - Related: rhbz#987355

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-1635.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0281");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker-cluster-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pacemaker-remote");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'pacemaker-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-cli-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-cluster-libs-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-cts-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-doc-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-libs-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-libs-devel-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-remote-1.1.10-14.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-cli-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-cluster-libs-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-cts-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-doc-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-libs-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-libs-devel-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pacemaker-remote-1.1.10-14.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pacemaker / pacemaker-cli / pacemaker-cluster-libs / etc');
}
