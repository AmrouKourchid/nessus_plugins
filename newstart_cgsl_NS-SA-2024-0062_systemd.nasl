#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0062. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206847);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id("CVE-2022-2526", "CVE-2023-26604");

  script_name(english:"NewStart CGSL MAIN 6.02 : systemd Multiple Vulnerabilities (NS-SA-2024-0062)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has systemd packages installed that are affected by multiple
vulnerabilities:

  - A use-after-free vulnerability was found in systemd. This issue occurs due to the on_stream_io() function
    and dns_stream_complete() function in 'resolved-dns-stream.c' not incrementing the reference counting for
    the DnsStream object. Therefore, other functions and callbacks called can dereference the DNSStream
    object, causing the use-after-free when the reference is still used later. (CVE-2022-2526)

  - A vulnerability was found in the systemd package. The systemd package does not adequately block local
    privilege escalation for some Sudo configurations, for example, plausible sudoers files, in which the
    systemctl status command may be executed. Specifically, systemd does not set LESSSECURE to 1, and thus
    other programs may be launched from the less program. This issue presents a substantial security risk when
    running systemctl from Sudo because less executes as root when the terminal size is too small to show the
    complete systemctl output. (CVE-2023-26604)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0062");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-2526");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-26604");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL systemd packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2526");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:systemd-udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'systemd-239-45.el8_4.2.cgslv6_2.21.gd25af2b',
    'systemd-container-239-45.el8_4.2.cgslv6_2.21.gd25af2b',
    'systemd-devel-239-45.el8_4.2.cgslv6_2.21.gd25af2b',
    'systemd-libs-239-45.el8_4.2.cgslv6_2.21.gd25af2b',
    'systemd-pam-239-45.el8_4.2.cgslv6_2.21.gd25af2b',
    'systemd-udev-239-45.el8_4.2.cgslv6_2.21.gd25af2b'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'systemd');
}
