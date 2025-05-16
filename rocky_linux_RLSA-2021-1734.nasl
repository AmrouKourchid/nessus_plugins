#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1734.
##

include('compat.inc');

if (description)
{
  script_id(184935);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id(
    "CVE-2020-14372",
    "CVE-2020-25632",
    "CVE-2020-25647",
    "CVE-2020-27749",
    "CVE-2020-27779",
    "CVE-2021-20225",
    "CVE-2021-20233"
  );
  script_xref(name:"IAVA", value:"2020-A-0349");
  script_xref(name:"RLSA", value:"2021:1734");

  script_name(english:"Rocky Linux 8 : shim (RLSA-2021:1734)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has a package installed that is affected by multiple vulnerabilities as referenced in the
RLSA-2021:1734 advisory.

  - A flaw was found in grub2 in versions prior to 2.06, where it incorrectly enables the usage of the ACPI
    command when Secure Boot is enabled. This flaw allows an attacker with privileged access to craft a
    Secondary System Description Table (SSDT) containing code to overwrite the Linux kernel lockdown variable
    content directly into memory. The table is further loaded and executed by the kernel, defeating its Secure
    Boot lockdown and allowing the attacker to load unsigned code. The highest threat from this vulnerability
    is to data confidentiality and integrity, as well as system availability. (CVE-2020-14372)

  - A flaw was found in grub2 in versions prior to 2.06. The rmmod implementation allows the unloading of a
    module used as a dependency without checking if any other dependent module is still loaded leading to a
    use-after-free scenario. This could allow arbitrary code to be executed or a bypass of Secure Boot
    protections. The highest threat from this vulnerability is to data confidentiality and integrity as well
    as system availability. (CVE-2020-25632)

  - A flaw was found in grub2 in versions prior to 2.06. During USB device initialization, descriptors are
    read with very little bounds checking and assumes the USB device is providing sane values. If properly
    exploited, an attacker could trigger memory corruption leading to arbitrary code execution allowing a
    bypass of the Secure Boot mechanism. The highest threat from this vulnerability is to data confidentiality
    and integrity as well as system availability. (CVE-2020-25647)

  - A flaw was found in grub2 in versions prior to 2.06. Variable names present are expanded in the supplied
    command line into their corresponding variable contents, using a 1kB stack buffer for temporary storage,
    without sufficient bounds checking. If the function is called with a command line that references a
    variable with a sufficiently large payload, it is possible to overflow the stack buffer, corrupt the stack
    frame and control execution which could also circumvent Secure Boot protections. The highest threat from
    this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2020-27749)

  - A flaw was found in grub2 in versions prior to 2.06. The cutmem command does not honor secure boot locking
    allowing an privileged attacker to remove address ranges from memory creating an opportunity to circumvent
    SecureBoot protections after proper triage about grub's memory layout. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-27779)

  - A flaw was found in grub2 in versions prior to 2.06. The option parser allows an attacker to write past
    the end of a heap-allocated buffer by calling certain commands with a large number of specific short forms
    of options. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2021-20225)

  - A flaw was found in grub2 in versions prior to 2.06. Setparam_prefix() in the menu rendering code performs
    a length calculation on the assumption that expressing a quoted single quote will require 3 characters,
    while it actually requires 4 characters which allows an attacker to corrupt memory by one byte for each
    quote in the input. The highest threat from this vulnerability is to data confidentiality and integrity as
    well as system availability. (CVE-2021-20233)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1734");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1873150");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1879577");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1886936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1899966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1900698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1924696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1926263");
  script_set_attribute(attribute:"solution", value:
"Update the affected shim-unsigned-aarch64 package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20233");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:shim-unsigned-aarch64");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'shim-unsigned-aarch64-15-7.el8.1.1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'shim-unsigned-aarch64');
}
