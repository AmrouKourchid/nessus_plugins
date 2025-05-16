#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2283.
##

include('compat.inc');

if (description)
{
  script_id(175703);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2022-30629", "CVE-2022-41717");
  script_xref(name:"IAVB", value:"2022-B-0059-S");

  script_name(english:"Oracle Linux 9 : skopeo (ELSA-2023-2283)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2283 advisory.

    [2:1.11.2-0.1]
    - update to the latest content of https://github.com/containers/skopeo/tree/release-1.11
      (https://github.com/containers/skopeo/commit/3f98753)
    - Related: #2124478

    [2:1.11.1-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.11.1
    - Related: #2124478

    [2:1.11.0-1]
    - update to 1.11.0 release
    - Related: #2124478

    [2:1.11.0-0.4]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/b3b2c73)
    - Related: #2124478

    [2:1.11.0-0.3]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/fe15a36)
    - Related: #2124478

    [2:1.11.0-0.2]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/8e09e64)
    - Related: #2124478

    [2:1.11.0-0.1]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/2817510)
    - Related: #2124478

    [2:1.10.0-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.10.0
    - Related: #2124478

    [2:1.9.3-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.9.3
    - Related: #2124478

    [2:1.9.2-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.9.2
    - Related: #2061316

    [2:1.9.1-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.9.1
    - Related: #2061316

    [2:1.9.0-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.9.0
    - Related: #2061316

    [2:1.8.0-4]
    - Re-enable debuginfo
    - Related: #2061316

    [2:1.8.0-3]
    - BuildRequires: /usr/bin/go-md2man
    - Related: #2061316

    [2:1.8.0-2]
    - enable LTO
    - Related: #1988128

    [2:1.8.0-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.8.0
    - Related: #2061316

    [2:1.7.0-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.7.0
    - Related: #2061316

    [2:1.6.1-4]
    - add tags: classic (Ed Santiago)
    - Related: #2061316

    [2:1.6.1-3]
    - remove BATS from required packages (Ed Santiago)
    - Related: #2061316

    [2:1.6.1-2]
    - be sure to install BATS before gating tests are executed
      (thanks to Ed Santiago)
    - Related: #2061316

    [2:1.6.1-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.6.1
    - Related: #2000051

    [2:1.6.0-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.6.0
    - Related: #2000051

    [2:1.5.2-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.5.2
    - Related: #2000051

    [2:1.5.1-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.5.1
    - Related: #2000051

    [2:1.5.1-0.9]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/4acc9f0)
    - Related: #2000051

    [2:1.5.1-0.8]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/c2732cb)
    - Related: #2000051

    [2:1.5.1-0.7]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/01e58f8)
    - Related: #2000051

    [2:1.5.1-0.6]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/8f64c04)
    - Related: #2000051

    [2:1.5.1-0.5]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/8182255)
    - Related: #2000051

    [2:1.5.1-0.4]
    - bump Epoch to preserve upgrade patch from RHEL8
    - Related: #2000051

    [1:1.5.1-0.3]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/9c9a9f3)
    - Related: #2000051

    [1:1.5.1-0.2]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/116e75f)
    - Related: #2000051

    [1:1.5.1-0.1]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/fc81803)
    - Related: #2000051

    [1:1.4.1-0.14]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/ff88d3f)
    - Related: #2000051

    [1:1.4.1-0.13]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/a95b0cc)
    - Related: #2000051

    [1:1.4.1-0.12]
    - add skopeo tests from Fedora
    - Related: #2000051

    [1:1.4.1-0.11]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/53cf287)
    - Related: #2000051

    [1:1.4.1-0.10]
    - add gating.yaml
    - Related: #2000051

    [1:1.4.1-0.9]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/86fa758)
    - Related: #2000051

    [1:1.4.1-0.8]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/2c2e5b7)
    - Related: #2000051

    [1:1.4.1-0.7]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/25d3e7b)
    - Related: #2000051

    [1:1.4.1-0.6]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/c5a5199)
    - Related: #2000051

    [1:1.4.1-0.5]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/db1e814)
    - Related: #2000051

    [1:1.4.1-0.4]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/31b8981)
    - Related: #2000051

    [1:1.4.1-0.3]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/177443f)
    - Related: #2000051

    [1:1.4.1-0.2]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/30f208e)
    - Related: #2000051

    [1:1.4.1-0.1]
    - update to the latest content of https://github.com/containers/skopeo/tree/main
      (https://github.com/containers/skopeo/commit/47b8082)
    - Related: #2000051

    [1:1.4.1-1]
    - rebuild with containers-common dep fixed
    - Related: #2000051

    [1:1.4.0-7]
    - Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
      Related: rhbz#1991688

    [1:1.4.0-6]
    - be sure short-name-mode is permissive in RHEL8
    - Related: #1970747

    [1:1.4.0-5]
    - don't define short-name-mode in RHEL8
    - Related: #1970747

    [1:1.4.0-4]
    - put both RHEL8 and RHEL9 conditional configurations into update.sh
    - Related: #1970747

    [1:1.4.0-3]
    - update vendored components
    - always require runc on RHEL8 or lesser
    - Related: #1970747

    [1:1.4.0-2]
    - update to the latest content of https://github.com/containers/skopeo/tree/release-1.4
      (https://github.com/containers/skopeo/commit/a44da44)
    - Related: #1970747

    [1:1.4.0-1]
    - update to 1.4.0 release and switch to the release-1.4 maint branch
    - Related: #1970747

    [1:1.4.0-0.2]
    - update vendored components
    - ship /etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release only on non-RHEL and
      CentOS distros
    - Related: #1970747

    [1:1.4.0-0.1]
    - switch to the main branch of skopeo
    - Related: #1970747

    [1:1.3.1-9]
    - Add support for signed RHEL images, enabled by default
    - Related: #1970747

    [1:1.3.1-8]
    - update seccomp.json from Fedora to allow clone3 to pass
    - Related: #1970747

    [1:1.3.1-7]
    - update shortnames from Pyxis
    - put RHEL9/UBI9 images into overrides
    - Related: #1970747

    [1:1.3.1-6]
    - correct name of the option is 'short-name-mode' not 'short-names-mode'
    - Related: #1970747

    [1:1.3.1-5]
    - handle CentOS Stream while updating vendored components
    - Related: #1970747

    [1:1.3.1-4]
    - update to the latest content of https://github.com/containers/skopeo/tree/release-1.3
      (https://github.com/containers/skopeo/commit/038f70e)
    - Related: #1970747

    [1:1.3.1-3]
    - update registries.conf to be consistent with upstream
    - Related: #1970747

    [1:1.3.1-2]
    - consume content from the release-1.3 upstream branch
    - Related: #1970747

    [1:1.3.1-1]
    - update to https://github.com/containers/skopeo/releases/tag/v1.3.1
    - Related: #1970747

    [1:1.3.0-7]
    - Rebuilt for RHEL 9 BETA for openssl 3.0
      Related: rhbz#1971065

    [1:1.3.0-6]
    - set short-names-mode = 'enforcing' in registries.conf
    - Resolves: #1971752

    [1:1.3.0-5]
    - configure for RHEL9
    - Related: #1970747

    [1:1.3.0-4]
    - add missing containers-mounts.conf.5.md file to git
    - don't list/install the same doc twice
    - Related: #1970747

    [1:1.3.0-3]
    - update to new versions of vendored components
    - fail is there is an issue in communication with Pyxis API
    - understand devel branch in update.sh script, use pkg wrapper
    - sync with Pyxis
    - use containers-mounts.conf.5.md from containers/common
    - Related: #1970747

    [1:1.2.2-4]
    - Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

    [1:1.2.2-3]
    - disable LTO again

    [1:1.2.2-2]
    - use rhel-shortnames only from trusted registries
    - sync with config files from current versions of vendored projects

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2283.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected skopeo and / or skopeo-tests packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30629");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:skopeo-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    {'reference':'skopeo-1.11.2-0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'skopeo-tests-1.11.2-0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'skopeo-1.11.2-0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'skopeo-tests-1.11.2-0.1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'skopeo / skopeo-tests');
}
