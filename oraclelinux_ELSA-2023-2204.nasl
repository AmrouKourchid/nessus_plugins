#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2204.
##

include('compat.inc');

if (description)
{
  script_id(175721);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-27664",
    "CVE-2022-41715",
    "CVE-2022-41717"
  );
  script_xref(name:"IAVB", value:"2022-B-0042-S");
  script_xref(name:"IAVB", value:"2022-B-0059-S");

  script_name(english:"Oracle Linux 9 : Image / Builder (ELSA-2023-2204)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2204 advisory.

    cockpit-composer
    [45-1.0.1]
    - Make per page documentation links point to Oracle Linux [Orabug: 32013095], [Orabug:34398922]

    [45-1]
    - New upstream release

    [44-1]
    - New upstream release

    [43-1]
    - New upstream release

    [42-1]
    - New upstream release

    osbuild
    [81-1]
    - New upstream release

    [80-1]
    - New upstream release

    [79-1]
    - New upstream release

    [78-1]
    - New upstream release

    [77-1]
    - New upstream release

    [76-1]
    - New upstream release

    [75-1]
    - New upstream release

    [74-1]
    - New upstream release

    [73-1]
    - New upstream release

    [72-1]
    - New upstream release

    [71-1]
    - New upstream release

    [70-1]
    - New upstream release

    [69-1]
    - New upstream release

    osbuild-composer
    [76-2]
    - distro/rhel: add payload repos to os package set (rhbz#2177699)
    - Manifest: always set kernel options in grub2 stage (rhbz#2162299)

    [76-1]
    - New upstream release

    [75-1]
    - New upstream release

    [74-1]
    - New upstream release

    [73-1]
    - New upstream release

    [72-1]
    - New upstream release

    [71-1]
    - New upstream release

    [70-1]
    - New upstream release

    [69-1]
    - New upstream release

    [68-1]
    - New upstream release

    [67-2]
    - Fix functional tests to make them pass in RHEL-9.2 gating

    [67-1]
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

    weldr-client
    [35.9-1]
    - Copy rhel-92.json test repository from osbuild-composer
    - Update osbuild-composer test repositories from osbuild-composer
    - New release: 35.9 (bcl)
      Resolves: rhbz#2164560
    - tests: Replace os.MkdirTemp with t.TempDir (bcl)
    - blueprint save: Allow overriding bad blueprint names (bcl)
    - tests: Clean up checking err in tests (bcl)
    - composer-cli: Implement blueprints diff (bcl)
    - saveBlueprint: Return the filename to the caller (bcl)
    - composer-cli: Add tests for using --commit with old servers (bcl)
    - weldr: Return error about the blueprints change route (bcl)
    - weldr: Save the http status code as part of APIResponse (bcl)
    - Add --commit support to blueprints save (bcl)
    - Add --commit to blueprints show (bcl)
    - gitleaks: Exclude the test password used in tests (bcl)
    - ci: add tags to AWS instances (tlavocat)
    - Update github.com/BurntSushi/toml to 1.2.1
    - Update github.com/stretchr/testify to 1.8.1
    - Update bump github.com/spf13/cobra to 1.6.1
    - New release: 35.8 (bcl)
    - completion: Remove providers from bash completion script (bcl)
    - completion: Filter out new headers from compose list (bcl)
    - docs: Remove unneeded Long descriptions (bcl)
    - docs: Use a custom help template (bcl)
    - docs: Add more command documentation (bcl)
    - cmdline: Add package glob support to modules list command (bcl)
    - workflow: Add govulncheck on go v1.18 (bcl)
    - tests: Update to use golangci-lint 1.49.0 (bcl)
    - New release: 35.7 (bcl)
    - spec: Move %gometa macro above %gourl (bcl)
    - weldr: When starting a compose pass size as bytes, not MiB (bcl)
    - tests: Use correct size value in bytes for test (bcl)
    - workflow: Add Go 1.18 to text matrix (bcl)
    - Replace deprecated ioutil functions (bcl)
    - New release: 35.6 (bcl)
    - tests: Update tests for osbuild-composer changes (bcl)
    - CMD: Compose status format (eloy.coto)
    - CMD: Compose list format (eloy.coto)
    - tests: Update tests to check for JSON list output (bcl)
    - composer-cli: Change JSON output to be a list of objects (bcl)
    - weldr: Simplify the old ComposeLog, etc. functions (bcl)
    - composer-cli: Add --filename to blueprints freeze save command (bcl)
    - composer-cli: Add --filename to blueprints save command (bcl)
    - composer-cli: Add --filename to compose logs command (bcl)
    - composer-cli: Add --filename to compose image command (bcl)
    - composer-cli: Add --filename to compose metadata command (bcl)
    - composer-cli: Add --filename to compose results command (bcl)
    - weldr: Add saving to a new filename to GetFilePath function (bcl)
    - github: Fix issue with codecov and forced pushes in PRs (bcl)
    - Use golangci-lint 1.45.2 in workflow (bcl)
    - Run workflow tests for go 1.16.x and 1.17.x (bcl)
    - Move go.mod to go 1.16 (bcl)
    - workflows/trigger-gitlab: run Gitlab CI in new image-builder project (jrusz)
    - Update GitHub actions/setup-go to 3
    - Update GitHub actions/checkout to 3

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2204.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2880");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/15");

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
    {'reference':'cockpit-composer-45-1.0.1.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'osbuild-81-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-76-2.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-core-76-2.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-dnf-json-76-2.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-worker-76-2.el9_2', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-luks2-81-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-lvm2-81-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-ostree-81-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-selinux-81-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-osbuild-81-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'weldr-client-35.9-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-76-2.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-core-76-2.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-dnf-json-76-2.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-worker-76-2.el9_2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-luks2-81-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-lvm2-81-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-ostree-81-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-selinux-81-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-osbuild-81-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'weldr-client-35.9-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
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
