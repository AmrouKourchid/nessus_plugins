#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0014. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135762);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/15");

  script_cve_id(
    "CVE-2019-14816",
    "CVE-2019-14895",
    "CVE-2019-14898",
    "CVE-2019-14901",
    "CVE-2019-17133"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel-rt Multiple Vulnerabilities (NS-SA-2020-0014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel-rt packages installed that are affected
by multiple vulnerabilities:

  - A vulnerability was found in the Linux kernel's Marvell
    WiFi chip driver. Where, while parsing vendor-specific
    informational attributes, an attacker on the same WiFi
    physical network segment could cause a system crash,
    resulting in a denial of service, or potentially execute
    arbitrary code. This flaw affects the network interface
    at the most basic level meaning the attacker only needs
    to affiliate with the same network device as the
    vulnerable system to create an attack path.
    (CVE-2019-14816)

  - A heap-based buffer overflow was discovered in the Linux
    kernel's Marvell WiFi chip driver. The flaw could occur
    when the station attempts a connection negotiation
    during the handling of the remote devices country
    settings. This could allow the remote device to cause a
    denial of service (system crash) or possibly execute
    arbitrary code. (CVE-2019-14895)

  - No description is available for this CVE.
    (CVE-2019-14898)

  - A heap overflow flaw was found in the Linux kernel's
    Marvell WiFi chip driver. The vulnerability allows a
    remote attacker to cause a system crash, resulting in a
    denial of service, or execute arbitrary code. The
    highest threat with this vulnerability is with the
    availability of the system. If code execution occurs,
    the code will run with the permissions of root. This
    will affect both confidentiality and integrity of files
    on the system. (CVE-2019-14901)

  - A vulnerability was found in the Linux kernel's generic
    WiFi ESSID handling implementation. The flaw allows a
    system to join a wireless network where the ESSID is
    longer than the maximum length of 32 characters, which
    can cause the system to crash or execute code.
    (CVE-2019-17133)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0014");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel-rt packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005"
  ],
  "CGSL MAIN 5.04": [
    "kernel-rt-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debug-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-debuginfo-common-x86_64-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-doc-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-devel-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-kvm-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005",
    "kernel-rt-trace-kvm-debuginfo-3.10.0-693.21.1.rt56.639.el7.cgslv5_4.30.404.g206c005"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-rt");
}
