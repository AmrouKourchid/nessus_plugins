#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2023:1584.
##

include('compat.inc');

if (description)
{
  script_id(179416);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id(
    "CVE-2022-4269",
    "CVE-2022-4378",
    "CVE-2023-0266",
    "CVE-2023-0386"
  );
  script_xref(name:"ALSA", value:"2023:1584");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"AlmaLinux 8 : kernel-rt (ALSA-2023:1584)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ALSA-2023:1584 advisory.

  - A flaw was found in the Linux kernel Traffic Control (TC) subsystem. Using a specific networking
    configuration (redirecting egress packets to ingress using TC action mirred) a local unprivileged user
    could trigger a CPU soft lockup (ABBA deadlock) when the transport protocol in use (TCP or SCTP) does a
    retransmission, resulting in a denial of service condition. (CVE-2022-4269)

  - A stack overflow flaw was found in the Linux kernel's SYSCTL subsystem in how a user changes certain
    kernel parameters and variables. This flaw allows a local user to crash or potentially escalate their
    privileges on the system. (CVE-2022-4378)

  - A use after free vulnerability exists in the ALSA PCM package in the Linux Kernel.
    SNDRV_CTL_IOCTL_ELEM_{READ|WRITE}32 is missing locks that can be used in a use-after-free that can result
    in a priviledge escalation to gain ring0 access from the system user. We recommend upgrading past commit
    56b88b50565cd8b946a2d00b0c83927b7ebb055e (CVE-2023-0266)

  - A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with
    capabilities was found in the Linux kernel's OverlayFS subsystem in how a user copies a capable file from
    a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges
    on the system. (CVE-2023-0386)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/8/ALSA-2023-1584.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0386");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation via CVE-2023-0386');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(120, 131, 282, 416, 787, 833);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:8::realtime");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 8.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

if (get_one_kb_item('Host/ksplice/kernel-cves'))
{
  rm_kb_item(name:'Host/uptrack-uname-r');
  var cve_list = make_list('CVE-2022-4269', 'CVE-2022-4378', 'CVE-2023-0266', 'CVE-2023-0386');
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ALSA-2023:1584');
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}
var pkgs = [
    {'reference':'kernel-rt-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-core-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-core-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-devel-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-kvm-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-devel-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-kvm-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-rt-modules-extra-4.18.0-425.19.2.rt7.230.el8_7', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel-rt / kernel-rt-core / kernel-rt-debug / kernel-rt-debug-core / etc');
}
