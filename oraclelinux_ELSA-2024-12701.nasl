#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12701.
##

include('compat.inc');

if (description)
{
  script_id(208037);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/02");

  script_cve_id("CVE-2024-7259");

  script_name(english:"Oracle Linux 8 : ovirt-engine (ELSA-2024-12701)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2024-12701 advisory.

    [4.4.10.7-1.0.33]
    - Fix external providers properties observability

    [4.4.10.7-1.0.32]
    - Upgrade bundled frontend dependency of jquery-ui

    [4.4.10.7-1.0.31]
    - Allow enrolling certificates in non-responsive state and Extend the lifetime of non-web certificates

    [4.4.10.7-1.0.30]
    - Fix network exception handling and fencing flow logic.

    [4.4.10.7-1.0.29]
    - Fixing the manage events form email display

    [4.4.10.7-1.0.28]
    - Remove taa-no from Secure Skylake Server

    [4.4.10.7-1.0.27]
    - Updating the jquery to 3.6.0

    [4.4.10.7-1.0.26]
    - Check locale for path traversal character

    [4.4.10.7-1.0.25]
    - Hide the icons directory from listable directories

    [4.4.10.7-1.0.24]
    - Fixed the packing of ova where ovf length was changed after encoding

    [4.4.10.7-1.0.23]
    - Fixed the issue of renewing vm-console-proxy and ovn certificates during engine-setup

    [4.4.10.7-1.0.22]
    - Fix the engine url for vmconsole to use https protocol

    [4.4.10.7-1.0.21]
    - Fix classpath for SecureByteArrayOutputStream after apache-sshd-2.9 update

    [4.4.10.7-1.0.20]
    - Wait for loop device to be available

    [4.4.10.7-1.0.19]
    - Clean old nvram file on vm emulator update to uefi secure boot

    [4.4.10.7-1.0.18]
    - Added support to use postgresql-jdbc-42.2.14-1 and spring framework 5.3.19
    - Cleanup the spec file to remove unneeded or commented lines

    [4.4.10.7-1.0.17]
    - Stopping the ovirt-engine-dwh service and setting the DwhCurrentlyRunning to 0 when changing password
    encryption from md5 to scram-sha-256.

    [4.4.10.7-1.0.16]
    - Included the condition of origin as NULL while inserting the data in vm_ovf_generations table

    [4.4.10.7-1.0.15]
    - Fix to parse both uppercase and camelcase instanceID in OvfReader

    [4.4.10.7-1.0.14]
    - Back Port from upstream 4.5 - https://gerrit.ovirt.org/c/ovirt-engine/+/116317/

    [4.4.10.7-1.0.13]
    -  Remove movirt as it is deprecated upstream

    [4.4.10.7-1.0.12]
    - Changing the password ecryption type in postgres from md5 to scram-sha-256

    [4.4.10.7-1.0.11]
    -  Add NumOfPciExpressPorts as configurable attribute

    [4.4.10.7-1.0.10]
    - Forward port - Support for Windows 11 and Windows Server 2022

    [4.4.10.7-1.0.9]
    - Forward port from 4.3.6.6-1.0.16, added Skylake-Server-noTSX-IBRS and Cascadelake-Server-noTSX CPU Types

    [4.4.10.7-1.0.8]
    -  Forward Port - Fix qxl video

    [4.4.10.7-1.0.7]
    -  Forward Port - Fix NPE during ova import operation

    [4.4.10.7-1.0.6]
    -  Forward Port from 4.3 - Handle ova when origin is null and storage disk is block

    [4.4.10.7-1.0.5]
    -  Forward Port from 4.3 - Remove unnecessary name length restriction for templates.

    [4.4.10.7-1.0.4]
    -  Port forward - Add hsts response header to httpd conf

    [4.4.10.7-1.0.3]
    -  Remove memory limit

    [4.4.10.7-1.0.2]
    -  Fix OS detection

    [4.4.10.7]
    - Bump version to 4.4.10.7

    [4.4.10.6]
    - Bump version to 4.4.10.6

    [4.4.10.5]
    - Bump version to 4.4.10.5

    [4.4.10.4]
    - Bump version to 4.4.10.4

    [4.4.10.3]
    - Bump version to 4.4.10.3

    [4.4.10.2]
    - Bump version to 4.4.10.2

    [4.4.10.1]
    - Bump version to 4.4.10.1

    [4.4.10]
    - Bump version to 4.4.10

    [4.4.9.2]
    - Bump version to 4.4.9.2

    [4.4.9.1]
    - Bump version to 4.4.9.1

    [4.4.9]
    - Bump version to 4.4.9

    [4.4.8.4]
    - Bump version to 4.4.8.4

    [4.4.8.3]
    - Bump version to 4.4.8.3

    [4.4.8.2]
    - Bump version to 4.4.8.2

    [4.4.8.1]
    - Bump version to 4.4.8.1

    [4.4.8]
    - Bump version to 4.4.8

    [4.4.7.6]
    - Bump version to 4.4.7.6

    [4.4.7.5]
    - Bump version to 4.4.7.5

    [4.4.7.4]
    - Bump version to 4.4.7.4

    [4.4.7.3]
    - Bump version to 4.4.7.3

    [4.4.7.2]
    - Bump version to 4.4.7.2

    [4.4.7.1]
    - Bump version to 4.4.7.1

    [4.4.7]
    - Bump version to 4.4.7

    [4.4.6.6]
    - Bump version to 4.4.6.6

    [4.4.6.5]
    - Bump version to 4.4.6.5

    [4.4.6.4]
    - Bump version to 4.4.6.4

    [4.4.6.3]
    - Bump version to 4.4.6.3

    [4.4.6.2]
    - Bump version to 4.4.6.2

    [4.4.6.1]
    - Bump version to 4.4.6.1

    [4.4.6]
    - Bump version to 4.4.6

    [4.4.5.8]
    - Bump version to 4.4.5.8

    [4.4.5.7]
    - Bump version to 4.4.5.7

    [4.4.5.6]
    - Bump version to 4.4.5.6

    [4.4.5.5]
    - Bump version to 4.4.5.5

    [4.4.5.4]
    - Bump version to 4.4.5.4

    [4.4.5.3]
    - Bump version to 4.4.5.3

    [4.4.5.2]
    - Bump version to 4.4.5.2

    [4.4.5.1]
    - Bump version to 4.4.5.1

    [4.4.5]
    - Bump version to 4.4.5

    [4.4.4.5]
    - Bump version to 4.4.4.5

    [4.4.4.4]
    - Bump version to 4.4.4.4

    [4.4.4.3]
    - Bump version to 4.4.4.3

    [4.4.4.2]
    - Bump version to 4.4.4.2

    [4.4.4.1]
    - Bump version to 4.4.4.1

    [4.4.4]
    - Bump version to 4.4.4

    [4.4.3.11]
    - Bump version to 4.4.3.11

    [4.4.3.10]
    - Bump version to 4.4.3.10

    [4.4.3.9]
    - Bump version to 4.4.3.9

    [4.4.3.8]
    - Bump version to 4.4.3.8

    [4.4.3.7]
    - Bump version to 4.4.3.7

    [4.4.3.6]
    - Bump version to 4.4.3.6

    [4.4.3.5]
    - Bump version to 4.4.3.5

    [4.4.3.4]
    - Bump version to 4.4.3.4

    [4.4.3.3]
    - Bump version to 4.4.3.3

    [4.4.3.2]
    - Bump version to 4.4.3.2

    [4.4.3.1]
    - Bump version to 4.4.3.1

    [4.4.3]
    - Bump version to 4.4.3

    [4.4.2.2]
    - Bump version to 4.4.2.2

    [4.4.2.1]
    - Bump version to 4.4.2.1

    [4.4.2]
    - Bump version to 4.4.2

    [4.4.1.8]
    - Bump version to 4.4.1.8

    [4.4.1.7]
    - Bump version to 4.4.1.7

    [4.4.1.6]
    - Bump version to 4.4.1.6

    [4.4.1.5]
    - Bump version to 4.4.1.5

    [4.4.1.4]
    - Bump version to 4.4.1.4

    [4.4.1.3]
    - Bump version to 4.4.1.3

    [4.4.1.2]
    - Bump version to 4.4.1.2

    [4.4.1.1]
    - Bump version to 4.4.1.1

    [4.4.1]
    - Bump version to 4.4.1

    [4.4.0.3]
    - Bump version to 4.4.0.3

    [4.4.0.2]
    - Bump version to 4.4.0.2

    [4.4.0.1]
    - Bump version to 4.4.0.1

    [4.4.0]
    - Bump version to 4.4.0

    [4.3.2.1]
    - Bump version to 4.3.2.1

    [4.3.2]
    - Bump version to 4.3.2

    [4.3.1.1]
    - Bump version to 4.3.1.1

    [4.3.1]
    - Bump version to 4.3.1

    [4.3.0.4]
    - Bump version to 4.3.0.4

    [4.3.0.3]
    - Bump version to 4.3.0.3

    [4.3.0.2]
    - Bump version to 4.3.0.2

    [4.3.0.1]
    - Bump version to 4.3.0.1

    [4.3.0]
    - Bump version to 4.3.0

    [4.2.8.2]
    - Bump version to 4.2.8.2

    [4.2.8.1]
    - Bump version to 4.2.8.1

    [4.2.8]
    - Bump version to 4.2.8

    [4.2.7.3]
    - Bump version to 4.2.7.3

    [4.2.7.2]
    - Bump version to 4.2.7.2

    [4.2.7.1]
    - Bump version to 4.2.7.1

    [4.2.7]
    - Bump version to 4.2.7

    [4.2.6.4]
    - Bump version to 4.2.6.4

    [4.2.6.3]
    - Bump version to 4.2.6.3

    [4.2.6.2]
    - Bump version to 4.2.6.2

    [4.2.6.1]
    - Bump version to 4.2.6.1

    [4.2.6]
    - Bump version to 4.2.6

    [4.2.5.2]
    - Bump version to 4.2.5.2

    [4.2.5.1]
    - Bump version to 4.2.5.1

    [4.2.5]
    - Bump version to 4.2.5

    [4.2.4.5]
    - Bump version to 4.2.4.5

    [4.2.4.4]
    - Bump version to 4.2.4.4

    [4.2.4.3]
    - Bump version to 4.2.4.3

    [4.2.4.2]
    - Bump version to 4.2.4.2

    [4.2.4.1]
    - Bump version to 4.2.4.1

    [4.2.4]
    - Bump version to 4.2.4

    [4.2.3.3]
    - Bump version to 4.2.3.3

    [4.2.3.2]
    - Bump version to 4.2.3.2

    [4.2.3.1]
    - Bump version to 4.2.3.1

    [4.2.3]
    - Bump version to 4.2.3

    [4.2.2.6]
    - Bump version to 4.2.2.6

    [4.2.2.5]
    - Bump version to 4.2.2.5

    [4.2.2.4]
    - Bump version to 4.2.2.4

    [4.2.2.3]
    - Bump version to 4.2.2.3

    [4.2.2.2]
    - Bump version to 4.2.2.2

    [4.2.2.1]
    - Bump version to 4.2.2.1

    [4.2.2]
    - Bump version to 4.2.2

    [4.2.1.4]
    - Bump version to 4.2.1.4

    [4.2.1.3]
    - Bump version to 4.2.1.3

    [4.2.1.2]
    - Bump version to 4.2.1.2

    [4.2.1.1]
    - Bump version to 4.2.1.1

    [4.2.1]
    - Bump version to 4.2.1

    [4.2.0.2]
    - Bump version to 4.2.0.2

    [4.2.0.1]
    - Bump version to 4.2.0.1

    [4.2.0]
    - Bump version to 4.2.0

    [4.1.0]
    - Add dependency for ovirt-engine-dashboard.
    - Bump version to 4.1.0

    [4.0.0]
    - Bump version to 4.0.0
    - Dropped Fedora < 22 and EL < 7 support

    [3.6.0]
    - Update dependencies and removed legacy provides / requires

    [3.3.0-1]
    - Bump version to 3.3.0

    [3.2.0-1]
    - Bump version to 3.2.0

    [3.1.0-3]
    - Removed image uploader, iso uploader, and log collector from this
      git repo.  The are now in their own respective ovirt.org git
      repos. BZ#803240.

    [3.1.0-2]
    - The ovirt-engine spec file did not previously contain a BuildRequires
      statement for the maven package. As a result in mock environments the
      build failed with an error when attempting to call the 'mvn' binary -
      BZ#807761.

    [3.1.0-1]
    - Adjust code for Jboss AS 7.1

    [3.1.0-1]
    - Moved all hard coded paths to macros

    [3.1.0-1]
    - Initial build
    - Cloned from RHEVM spec file

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12701.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:M/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::ovirt44");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-dbscripts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-health-check-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-restapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup-plugin-cinderlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup-plugin-imageio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup-plugin-ovirt-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup-plugin-ovirt-engine-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup-plugin-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-setup-plugin-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-tools-backup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-vmconsole-proxy-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-webadmin-portal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ovirt-engine-websocket-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ovirt-engine-lib");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'ovirt-engine-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-backend-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-dbscripts-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-health-check-bundler-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-restapi-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-base-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-plugin-cinderlib-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-plugin-imageio-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-plugin-ovirt-engine-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-plugin-ovirt-engine-common-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-plugin-vmconsole-proxy-helper-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-setup-plugin-websocket-proxy-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-tools-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-tools-backup-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-vmconsole-proxy-helper-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-webadmin-portal-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ovirt-engine-websocket-proxy-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ovirt-engine-lib-4.4.10.7-1.0.33.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ovirt-engine / ovirt-engine-backend / ovirt-engine-dbscripts / etc');
}
