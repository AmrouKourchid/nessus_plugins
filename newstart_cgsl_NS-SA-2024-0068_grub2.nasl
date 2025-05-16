#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0068. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206830);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/10");

  script_cve_id("CVE-2021-3981", "CVE-2022-28733");

  script_name(english:"NewStart CGSL MAIN 6.02 : grub2 Multiple Vulnerabilities (NS-SA-2024-0068)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has grub2 packages installed that are affected by multiple
vulnerabilities:

  - A flaw in grub2 was found where its configuration file, known as grub.cfg, is being created with the wrong
    permission set allowing non privileged users to read its content. This represents a low severity
    confidentiality issue, as those users can eventually read any encrypted passwords present in grub.cfg.
    (CVE-2021-3981)

  - A flaw was found in grub2 when handling IPv4 packets. This flaw allows an attacker to craft a malicious
    packet, triggering an integer underflow in grub code. Consequently, the memory allocation for handling the
    packet data may be smaller than the size needed. This issue causes an out-of-bands write during packet
    handling, compromising data integrity, confidentiality issues, a denial of service, and remote code
    execution. (CVE-2022-28733)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0068");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3981");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28733");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL grub2 packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3981");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-efi-x64-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-pc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-pc-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools-efi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:grub2-tools-minimal");
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
    'grub2-common-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-efi-x64-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-efi-x64-modules-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-pc-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-pc-modules-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-tools-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-tools-efi-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-tools-extra-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a',
    'grub2-tools-minimal-2.02-90.el8_3.1.cgslv6_2.14.g52ff5f0a'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'grub2');
}
