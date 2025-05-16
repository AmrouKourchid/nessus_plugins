#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2459.
##

include('compat.inc');

if (description)
{
  script_id(175679);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2022-41973");

  script_name(english:"Oracle Linux 9 : device-mapper-multipath (ELSA-2023-2459)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2023-2459 advisory.

    [0.8.7-20]
    - Add 0083-multipath.rules-fix-smart-bug-with-failed-valid-path.patch
    - Add 0084-libmultipath-limit-paths-that-can-get-wwid-from-envi.patch
    - Change how the installation dir for kpartx_id is specified
    - Resolves: bz #1926147

    [0.8.7-19]
    - Fix bugzilla linked to the changes (was previously linked to
      the wrong bug, 2162536)
    - Resolves: bz #2166467

    [0.8.7-18]
    - Add 0079-libmultipath-use-select_reload_action-in-select_acti.patch
    - Add 0080-libmultipath-select-resize-action-even-if-reload-is-.patch
    - Add 0081-libmultipath-cleanup-ACT_CREATE-code-in-select_actio.patch
    - Add 0082-libmultipath-keep-renames-from-stopping-other-multip.patch
    - Resolves: bz #2166467

    [0.8.7-17]
    - Add 0077-libmultipath-don-t-leak-memory-on-invalid-strings.patch
    - Add 0078-libmutipath-validate-the-argument-count-of-config-st.patch
    - Resolves: bz #2145225

    [0.8.7-16]
    - Add 0076-multipath.conf-5-remove-io-affinity-information.patch
    - Resolves: bz #2143125

    [0.8.7-15]
    - Add 0067-kpartx-hold-device-open-until-partitions-have-been-c.patch
      * Fixes bz #2141860
    - Add 0068-libmultipath-cleanup-remove_feature.patch
    - Add 0069-libmultipath-cleanup-add_feature.patch
    - Add 0070-multipath-tests-tests-for-adding-and-removing-featur.patch
    - Add 0071-libmultipath-fix-queue_mode-feature-handling.patch
    - Add 0072-multipath-tests-tests-for-reconcile_features_with_qu.patch
    - Add 0073-libmultipath-prepare-proto_id-for-use-by-non-scsi-de.patch
    - Add 0074-libmultipath-get-nvme-path-transport-protocol.patch
    - Add 0075-libmultipath-enforce-queue_mode-bio-for-nmve-tcp-pat.patch
      * Fixes bz #2033080
    - Resolves: bz #2033080, #2141860

    [0.8.7-14]
    - Add 0065-multipathd-ignore-duplicated-multipathd-command-keys.patch
      * Fixes bz #2133999
    - Add 0066-multipath-tools-use-run-instead-of-dev-shm.patch
      * Fixes bz #2133989
    - Resolves: bz #2133989, #2133999

    [0.8.7-13]
    - Add 0062-multipathd-factor-out-the-code-to-flush-a-map-with-n.patch
    - Add 0063-libmultipath-return-success-if-we-raced-to-remove-a-.patch
    - Add 0064-multipathd-Handle-losing-all-path-in-update_map.patch
    - Resolves: bz #2125357

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2459.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41973");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:device-mapper-multipath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:device-mapper-multipath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:device-mapper-multipath-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kpartx");
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
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'device-mapper-multipath-0.8.7-20.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'device-mapper-multipath-devel-0.8.7-20.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'device-mapper-multipath-libs-0.8.7-20.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kpartx-0.8.7-20.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'device-mapper-multipath-devel-0.8.7-20.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'device-mapper-multipath-libs-0.8.7-20.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kpartx-0.8.7-20.el9', 'cpu':'i686', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'device-mapper-multipath-0.8.7-20.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'device-mapper-multipath-devel-0.8.7-20.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'device-mapper-multipath-libs-0.8.7-20.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kpartx-0.8.7-20.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'device-mapper-multipath / device-mapper-multipath-devel / device-mapper-multipath-libs / etc');
}
