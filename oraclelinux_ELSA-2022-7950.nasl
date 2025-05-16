#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2022-7950.
##

include('compat.inc');

if (description)
{
  script_id(168114);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2022-32189");

  script_name(english:"Oracle Linux 9 : Image / Builder (ELSA-2022-7950)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2022-7950 advisory.

    cockpit-composer
    [41-1.0.1]
    - Make per page documentation links point to Oracle Linux [Orabug: 32013095], [Orabug:34398922]

    [41-1]
    - New upstream release

    [40-1]
    - New upstream release

    [39-1]
    - New upstream release

    [38-1]
    - New upstream release

    [37-1]
    - New upstream release

    [35-1]
    - New upstream release

    [34-1]
    - New upstream release

    [33-1]
    - Add support for OCI upload target
    - Update translations
    - Update dependencies

    [32-1]
    - Add Edge Raw, RHEL Installer, Edge Simplified Installer image types
    - Improve user account modal responsiveness
    - Update tests
    - Update minor NPM dependencies
    - Update translation files

    [31-1]
    - Add new ostree image types
    - Improve loading state when waiting for api responses
    - Improve notification system
    - Improve test stability
    - Update NPM dependencies
    - Update translations

    [30-3]
    - Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
      Related: rhbz#1991688

    [30-2]
    - Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

    [30-1]
    - Add and update translations
    - Update NPM dependencies
    - Improve test reliability

    [28-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

    [28-1]
    - Use sentence case rather than title case
    - Add and update tests
    - Update translations from weblate
    - Update minor NPM dependencies

    [27-1]
    - Improve test reliability
    - Update translations from weblate
    - Update minor NPM dependencies

    [26-1]
    - Add additional form validation for the Create Image Wizard
    - Improve page size dropdown styling
    - Update minor NPM dependencies
    - Improve code styling
    - Improve test reliability

    osbuild
    [65-1]
    - New upstream release

    [64-1]
    - New upstream release

    [63-1]
    - New upstream release

    [62-1]
    - New upstream release

    [61-1]
    - New upstream release

    [60-1]
    - New upstream release

    [59-1]
    - New upstream release

    [58-1]
    - New upstream release

    [57-1]
    - New upstream release

    [56-1]
    - New upstream release

    [55-1]
    - New upstream release

    [54-1]
    - New upstream release

    [53-1]
    - New upstream release

    [52-1]
    - New upstream release

    [50-1]
    - New upstream release

    [49-1]
    - New upstream release

    [48-1]
    - New upstream release

    [47-1]
    - New upstream release

    [46-1]
    - New upstream release

    [45-1]
    - New upstream release

    [44-1]
    - New upstream release

    [43-1]
    - New upstream release

    [42-1]
    - New upstream release

    [39-1]
    - New upstream release

    [35-1]
    - Upstream release 35

    [34-1]
    - Upstream release 34

    [33-1]
    - Upstream release 33

    [32-1]
    - Upstream release 32

    [31-1]
    - Upstream release 31

    [30-1]
    - Upstream release 30
    - Many new stages for building ostree-based raw images
    - Bootiso.mono stage was deprecated and split into smaller stages
    - Mounts are now represented as an array in a manifest
    - Various bug fixes and improvements to various stages

    [29-2]
    - Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
      Related: rhbz#1991688

    [29-1]
    - Upstream release 29
    - Adds host services
    - Adds modprobe and logind stage

    [27-3]
    - Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

    [27-2]
    - Include Fedora 35 runner (upstream commit 337e0f0)

    [27-1]
    - Upstream release 27
    - Various bug fixes related to the new container and installer
      stages introdcued in version 25 and 26.

    [26-1]
    - Upstream release 26
    - Support for building boot isos
    - Grub stage gained support for saved_entry to fix grub tooling

    [25-1]
    - Upstream release 25
    - First tech preview of the new manifest format. Includes
      various new stages and inputs to be able to build ostree
      commits contained in a oci archive.

    [24-1]
    - Upstream release 24
    - Turn on dependency generator for everything but runners
    - Include new input binaries

    [23-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

    [23-1]
    - Upstream release 23
    - Do not mangle shebangs for assemblers, runners & stages.

    [22-1]
    - Upstream release 22

    [21-1]
    - Upstream reelase 21

    osbuild-composer
    [62.1-1]
    - New upstream release

    [62-1]
    - New upstream release

    [60-1]
    - New upstream release

    [59-1]
    - New upstream release

    [58-1]
    - New upstream release

    [57-1]
    - New upstream release

    [55-1]
    - New upstream release

    [54-1]
    - New upstream release

    [53-1]
    - New upstream release

    [51-1]
    - New upstream release

    [46-1]
    - New upstream release

    [45-1]
    - New upstream release

    [44-1]
    - New upstream release

    [43-1]
    - New upstream release

    [42-1]
    - New upstream release

    [41-1]
    - New upstream release

    [40-1]
    - New upstream release

    [39-1]
    - New upstream release

    [38-1]
    - New upstream release

    * Tue Nov 02 2021 lavocatt - 37-1
    - New upstream release

    [36-1]
    - New upstream release

    [33-1]
    - New upstream release

    [32-1]
    - New upstream release

    [31-1]
    - New upstream release

    [30-2]
    - Rebuilt for IMA sigs, glibc 2.34, aarch64 flags
      Related: rhbz#1991688

    [30-1]
    - New upstream release

    [29-3]
    - Rebuilt for RHEL 9 BETA for openssl 3.0
      Related: rhbz#1971065

    [29-2]
    - Rebuilt for RHEL 9 BETA on Apr 15th 2021. Related: rhbz#1947937

    [29-1]
    - New upstream release

    [28-1]
    - New upstream release

    [27-1]
    - New upstream release

    [26-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_34_Mass_Rebuild

    [26-2]
    - Fix the compatibility with a new golang-github-azure-storage-blob 0.12

    [26-1]
    - New upstream release

    [25-1]
    - New upstream release

    [24-1]
    - New upstream release

    [23-1]
    - New upstream release

    [22-1]
    - New upstream release

    weldr-client
    [35.5-4]
    - tests: Add osbuild-composer repo file for RHEL 9.1
      Related: rhbz#2118831

    [35.5-3]
    - tests: Update tests for osbuild composer changes
      Resolves: rhbz#2118831

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2022-7950.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-32189");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer-dnf-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-luks2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-lvm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-ostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-osbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:weldr-client");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'cockpit-composer-41-1.0.1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'osbuild-65-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-62.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-core-62.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-dnf-json-62.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-worker-62.1-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-luks2-65-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-lvm2-65-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-ostree-65-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-selinux-65-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-osbuild-65-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'weldr-client-35.5-4.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-62.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-core-62.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-dnf-json-62.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-worker-62.1-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-luks2-65-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-lvm2-65-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-ostree-65-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-selinux-65-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-osbuild-65-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'weldr-client-35.5-4.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cockpit-composer / osbuild / osbuild-composer / etc');
}
