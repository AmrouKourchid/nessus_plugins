#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-1532.
##

include('compat.inc');

if (description)
{
  script_id(181108);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2011-3588", "CVE-2011-3589", "CVE-2011-3590");

  script_name(english:"Oracle Linux 6 : kexec-tools (ELSA-2011-1532)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has a package installed that is affected by multiple vulnerabilities as referenced in the
ELSA-2011-1532 advisory.

    [2.0.0-209.0.1.el6]
    - Make sure '--allow-missing' is effective by adding to MKDUMPRD_ARGS in
      kdump.sysconfig, kdump.sysconfig.i386, and kdump.sysconfig.x86_64 [12590865] [11678808]

    [2.0.0-209]
    - Improve debugfs mounting code, from Dave Young.
      Resolve bug 748748.

    [2.0.0-208]
    - Search DUP firmware directory too, from Caspar Zhang.
      Resolve bug 747233.

    [2.0.0-207]
    - Don't run kdump service on s390x, from Caspar Zhang.
      Resolve bug 746207.

    [2.0.0-206]
    - Fix some security flaws, resolve bug 743165.

    [2.0.0-205]
    - Fix a scriptlet failure in fence-agents, resolve bug 739050.

    [2.0.0-204]
    - Add new config 'force_rebuild', resolve bug 598067.

    [2.0.0-203]
    - Warn users to use maxcpus=1 instead of nr_cpus=1 for older
      kernels, resolve bug 727892.

    [2.0.0-202]
    - Pass 'noefi acpi_rsdp=X' to the second kernel, resolve bug 681796.

    [2.0.0-201]
    - Include patch 602 for rawbuild, resolve bug 708503.

    [2.0.0-200]
    - Remove the warning for reserved memory on x86, resolve BZ 731394.

    [2.0.0-199]
    - Add debug_mem_level debugging option, from Jan Stancek.
      Resolve Bug 734528.

    [2.0.0-198]
    - Fix the error message on /etc/cluster_iface,
      resolve bug 731236. From Ryan O'Hara.

    [2.0.0-197]
    - Add coordination between kdump and cluster fencing for long
      kernel panic dumps, resolve bug 585332. From Ryan O'Hara.

    [2.0.0-196]
    - Use nr_cpus=1 instead of maxcpus=1 on x86, resolve Bug 725484.

    [2.0.0-195]
    - Fix segfault on ppc machine with 1TB memory, resolve Bug 709441.

    [2.0.0-194]
    - Specify kernel version for every modprobe, resolve Bug 719105.

    [2.0.0-193]
    - Don't handle raid device specially, resolve Bug 707805.

    [2.0.0-192]
    - Read mdadm.conf correctly, resolve Bug 707805.

    [2.0.0-191]
    - Use makedumpfile as default core_collector for ssh dump.
      Resolve Bug 693025.

    [2.0.0-190]
    - Revert the previous patch, resolve Bug 701339.

    [2.0.0-189]
    - Disable THP in kdump kernel, resolve Bug 701339.

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-1532.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected kexec-tools package.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3590");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kexec-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'reference':'kexec-tools-2.0.0-209.0.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kexec-tools-2.0.0-209.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kexec-tools');
}
