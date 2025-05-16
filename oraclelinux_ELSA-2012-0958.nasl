#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0958 and 
# Oracle Linux Security Advisory ELSA-2012-0958 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68562);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2012-2664");
  script_bugtraq_id(54116);
  script_xref(name:"RHSA", value:"2012:0958");

  script_name(english:"Oracle Linux 6 : sos (ELSA-2012-0958)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has a package installed that is affected by a vulnerability as referenced in the
ELSA-2012-0958 advisory.

    [2.2-29.0.1.el6]
    - Direct traceroute to linux.oracle.com (John Haxby) [orabug 11713272]
    - Disable --upload option as it will not work with Oracle support
    - Check oraclelinux-release instead of redhat-release to get OS version (John Haxby) [bug 11681869]
    - Remove RH ftp URL and support email
    - add sos-oracle-enterprise.patch

    [2.2-29.el6]
    - Collect the swift configuration directory in gluster module
      Resolves: bz822442
    - Update IPA module and related plug-ins
      Resolves: bz812395

    [2.2-28.el6]
    - Collect mcelog files in the hardware module
      Resolves: bz810702

    [2.2-27.el6]
    - Add nfs statedump collection to gluster module
      Resolves: bz752549

    [2.2-26.el6]
    - Use wildcard to match possible libvirt log paths
      Resolves: bz814474

    [2.2-25.el6]
    - Add forbidden paths for new location of gluster private keys
      Resolves: bz752549

    [2.2-24.el6]
    - Fix katello and aeolus command string syntax
      Resolves: bz752666
    - Remove stray hunk from gluster module patch
      Resolves: bz784061

    [2.2-22.el6]
    - Correct aeolus debug invocation in CloudForms module
      Resolves: bz752666
    - Update gluster module for gluster-3.3
      Resolves: bz784061
    - Add additional command output to gluster module
      Resolves: bz768641
    - Add support for collecting gluster configuration and logs
      Resolves: bz752549

    [2.2-19.el6]
    - Collect additional diagnostic information for realtime systems
      Resolves: bz789096
    - Improve sanitization of RHN user and case number in report name
      Resolves: bz771393
    - Fix verbose output and debug logging
      Resolves: bz782339
    - Add basic support for CloudForms data collection
      Resolves: bz752666
    - Add support for Subscription Asset Manager diagnostics
      Resolves: bz752670

    [2.2-18.el6]
    - Collect fence_virt.conf in cluster module
      Resolves: bz760995
    - Fix collection of /proc/net directory tree
      Resolves: bz730641
    - Gather output of cpufreq-info when present
      Resolves: bz760424
    - Fix brctl showstp output when bridges contain multiple interfaces
      Resolves: bz751273
    - Add /etc/modprobe.d to kernel module
      Resolves: bz749919
    - Ensure relative symlink targets are correctly handled when copying
      Resolves: bz782589
    - Fix satellite and proxy package detection in rhn plugin
      Resolves: bz749262
    - Collect stderr output from external commands
      Resolves: bz739080
    - Collect /proc/cgroups in the cgroups module
      Resolve: bz784874
    - Collect /proc/irq in the kernel module
      Resolves: bz784862
    - Fix installed-rpms formatting for long package names
      Resolves: bz767827
    - Add symbolic links for truncated log files
      Resolves: bz766583
    - Collect non-standard syslog and rsyslog log files
      Resolves: bz771501
    - Use correct paths for tomcat6 in RHN module
      Resolves: bz749279
    - Obscure root password if present in anacond-ks.cfg
      Resolves: bz790402
    - Do not accept embedded forward slashes in RHN usernames
      Resolves: bz771393
    - Add new sunrpc module to collect rpcinfo for gluster systems
      Resolves: bz784061

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2012-0958.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected sos package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

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
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'sos-2.2-29.0.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'sos');
}
