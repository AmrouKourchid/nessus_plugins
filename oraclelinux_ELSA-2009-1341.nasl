#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2009-1341.
##

include('compat.inc');

if (description)
{
  script_id(181082);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2008-4579", "CVE-2008-6552");

  script_name(english:"Oracle Linux 5 : cman (ELSA-2009-1341)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2009-1341 advisory.

    [2.0.115-1]
    - RSA II fencing agent has been fixed.
    - Resolves: rhbz#493802

    [2.0.114-1]
    - local variable 'verbose_filename' referenced before assignment has been fixed
    - RSA II fencing agent has been fixed.
    - Resolves: rhbz#493802 rhbz#514758

    [2.0.113-1]
    - Limitations with 2-node fence_scsi are now properly documented in the man
      page.
    - Resolves: rhbz#512998

    [2.0.112-1]
    - The pexpect exception is now properly checked in fence agents.
    - Resolves: rhbz#501586

    [2.0.111-1]
    - cman_tool leave remove does now properly reduces quorum.
    - Resolves: rhbz#505258

    [2.0.110-1]
    - Updated fence_lpar man page to remove options that do not yet exist.
    - Resolves: rhbz#498045

    [2.0.108-1]
    - A semaphore leak in cman has been fixed.
    - Resolves: rhbz#505594

    [2.0.107-1]
    - Added man page for lpar fencing agent (fence_lpar).
    - Resolves: rhbz#498045

    [2.0.106-1]
    - The lssyscfg command can take longer than the shell timeout which will
      cause fencing to fail, we now wait longer for the lssyscfg command to
      complete.
    - Resolves: rhbz#504705

    [2.0.105-1]
    - The fencing agents no longer fail with pexpect exceptions.
    - Resolves: rhbz#501586

    [2.0.104-1]
    - Broadcast communcations are now possible with cman
    - fence_lpar can now login to IVM systems
    - Resolves: rhbz#502674 rhbz#492808

    [2.0.103-1]
    - fence_apc no longer fails with a pexpect exception
    - symlink vulnerabilities in fance_apc_snmp were fixed
    - The virsh fencing agent was added.
    - Resolves: rhbz#496629 rhbz#498952 rhbz#501586

    [2.0.102-1]
    - Correct return code is checked during disk scanning check.
    - Resolves: rhbz#484956

    [2.0.101-1]
    - The SCSI fence agent now verifies that sg_persist is installed properly.
    - The DRAC5 fencing agent now properly handles a modulename.
    - QDisk now logs warning messages if it appears it's I/O to shared storage
      is hung.
    - Resolves: rhbz#496724 rhbz#500450 rhbz#500567

    [2.0.100-1]
    - Support has been added for ePowerSwitch 8+ devices
    - cluster.conf files can now have more than 52 entries inside a block inside
    [block]
    - The output of the group_tool dump sub commands are no longer NULL padded.
    - Using device='' instead of label='' no longer causes qdiskd to incorrectly
      exit
    - The IPMI fencing agent has been modified to timeout after 10 seconds.  It is
      also now possible to specify a different timeout with the '-t' option.
    - The IPMI fencing agent now allows punctuation in the password
    - Quickly starting and stopping the cman service no longer causes the cluster
      membership to become inconsistent across the cluster
    - An issue with lock syncing causing 'receive_own from ...' errors in syslog
      has been fixed
    - An issue which caused gfs_controld to segfault when mounting hundreds of
      filesystems has been fixed
    - The LPAR fencing agent now properly reports status when an LPAR is in
      Open Firmware
    - The APC SNMP fencing agent now properly recognizes outletStatusOn and
      outletStatusOff returns codes from the SNMP agent
    - WTI Fencing agent can now connect to fencing devices with no password
    - The rps-10 fencing agent now properly performs a reboot when run with no
      options.
    - The IPMI fencing agent now supports different cipher types with the '-C'
      option
    - Qdisk now properly scans devices and partitions
    - Added support for LPAR/HMC v3
    - cman now checks to see if a new node has state to prevent killing the first
      node during cluster setup
    - service qdiskd start now works properly
    - The McData fence agent now works properly with the Sphereon 4500 model
    - The Egenera fence agent can now specify an ssh login name
    - APC Fence agent works with non-admin accounts with firmware 3.5.x
    - fence_xvmd now tries two methods to reboot a virtual machine
    - Connections to openais are now allowed from unprivileged CPG clients with
      user and group of 'ais'
    - Support has been added for Cisco 9124/9134 SAN switches
    - groupd no longer allows the default fence domain to be '0' which would cause
      rgmanager to hang
    - The RSA fence agent now supports ssh enabled RSA II devices
    - DRAC fence agent now works with iDRAC on the Dell M600 Blade Chassis
    - fence_drac5 now shows proper usage instructions
    - cman no longer uses the wrong node name when getnameinfo() fails
    - The SCSI fence agent now verifies that sg_persist is installed properly
    - Resolves: rhbz#467112 rhbz#468966 rhbz#470318 rhbz#276541 rhbz#447964 rhbz#472786 rhbz#474163
    rhbz#480401 rhbz#481566 rhbz#484095 rhbz#481664 rhbz#322291 rhbz#447497 rhbz#484956 rhbz#485700
    rhbz#485026 rhbz#485199 rhbz#470983 rhbz#488958 rhbz#487501 rhbz#491640 rhbz#480178 rhbz#485469
    rhbz#480836 rhbz#493207 rhbz#493802 rhbz#462390 rhbz#498329 rhbz#488565 rhbz#499871

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2009-1341.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected cman and / or cman-devel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-6552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cman-devel");
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
    {'reference':'cman-2.0.115-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cman-devel-2.0.115-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cman-2.0.115-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cman-devel-2.0.115-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cman / cman-devel');
}
