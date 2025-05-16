#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-1000.
##

include('compat.inc');

if (description)
{
  script_id(181107);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2010-3389");

  script_name(english:"Oracle Linux 5 : rgmanager (ELSA-2011-1000)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has a package installed that is affected by a vulnerability as referenced in the
ELSA-2011-1000 advisory.

    [2.0.52-21]
    - rgmanager: Fix bad passing of SFL_FAILURE up
      (fix_bad_passing_of_sfl_failure_up.patch)
      Resolves: rhbz#711521

    [2.0.52-20]
    - resource-agents: Improve LD_LIBRARY_PATH handling by SAP*
      (resource_agents_improve_ld_library_path_handling_by_sap*.patch)
      Resolves: rhbz#710637

    [2.0.52-19]
    - Fix changelog format
    - rgmanager: Fix reference count handling
      (fix_reference_count_handling.patch)
      Resolves: rhbz#692771

    [2.0.52-18]
    - resource-agents: postgres-8 resource agent does not detect a failed
      start of postgres server
      (postgres-8-Fix_pid_files.patch)
      Resolves: rhbz#663827

    [2.0.52-16]
    - rgmanager: Allow non-root clustat
      (allow_non_root_clustat.patch)
      Resolves: rhbz#510300
    - rgmanager: Initial commit of central proc + migration support
      (central_proc_+_migration_support.patch)
      Resolves: rhbz#525271
    - rgmanager: Make clufindhostname -i predictable
      (make_clufindhostname_i_predictable.patch)
      Resolves: rhbz#592613
    - resource-agents: Trim trailing slash for nfs clients
      (trim_trailing_slash_for_nfs_clients.patch)
      Resolves: rhbz#592624
    - rgmanager: Update last_owner on failover
      (update_last_owner_on_failover.patch)
      Resolves: rhbz#610483
    - rgmanager: Pause during exit if we stopped services
      (pause_during_exit_if_we_stopped_services.patch)
      Resolves: rhbz#619468
    - rgmanager: Fix quotaoff handling
      (fix_quotaoff_handling.patch)
      Resolves: rhbz#637678
    - resource-agents: Try force-unmount before fuser for netfs.sh
      (try_force_unmount_before_fuser_for_netfs_sh.patch)
      Resolves: rhbz#678494
    - rgmanager: Improve rgmanager's exclusive prioritization handling
      (improve_rgmanager_s_exclusive_prioritization_handling.patch)
      Resolves: rhbz#680256

    [2.0.52-15]
    - resource-agents: postgres-8 resource agent does not detect a failed
      start of postgres server
      (postgres-8-Do-not-send-TERM-signal-when-killing-post.patch)
      (postgres-8-Improve-testing-if-postgres-started-succe.patch)
      Resolves: rhbz#663827

    [2.0.52-14]
    - resource-agents: Fix problems when generating XML configuration file
      (rgmanager-Fix-problems-in-generated-XML-config-file.patch)
      Resolves: rhbz#637802

    [2.0.52-13]
    - resource-agents: Use literal quotes for tr calls
      (resource_agents_use_literal_quotes_for_tr_calls.patch)
      Resolves: rhbz#637154

    [2.0.52-12]
    - resource-agents: Use shutdown immediate in oracledb.sh
      (use_shutdown_immediate_in_oracledb_sh.patch)
      Resolves: rhbz#633992
    - rgmanager: Add path to rhev-check.sh
      (add_path_to_rhev_check_sh.patch)
      Resolves: rhbz#634225
    - rgmanager: Make clustat report correct version
      (make_clustat_report_correct_version.patch)
      Resolves: rhbz#654160

    [2.0.52-11]
    - resource-agents: Listen line in generated httpd.conf incorrect
      (resource-agents-Remove-netmask-from-IP-address-when.patch)
      Resolves: rhbz#675739
    - resource-agents: Disable updates to static routes by RHCS IP tooling
      (resource-agents-Add-option-disable_rdisc-to-ip.sh.patch)
      Resolves: rhbz#620700

    [2.0.52-10.1]
    - rgmanager: Fix nofailback when service is in 'starting' state
      (fix_nofailback_when_service_is_in_starting_state.patch)
      Resolves: rhbz#669440

    [2.0.52-10]
    - resource-agents: Problem with whitespace in mysql resource name
      (resource_agents_fix_whitespace_in_names.patch)
      Resolves: rhbz#632704

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-1000.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected rgmanager package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3389");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:rgmanager");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'rgmanager-2.0.52-21.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rgmanager-2.0.52-21.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'rgmanager');
}
