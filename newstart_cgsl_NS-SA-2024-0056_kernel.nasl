#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2024-0056. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206835);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/18");

  script_cve_id(
    "CVE-2020-12362",
    "CVE-2020-12464",
    "CVE-2020-24586",
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-25670",
    "CVE-2020-25671",
    "CVE-2020-26139",
    "CVE-2020-26141",
    "CVE-2020-26143",
    "CVE-2020-26144",
    "CVE-2020-26145",
    "CVE-2020-26147",
    "CVE-2020-29660",
    "CVE-2020-36158",
    "CVE-2021-3564",
    "CVE-2021-3573",
    "CVE-2021-3600",
    "CVE-2021-3679",
    "CVE-2021-3732",
    "CVE-2021-20194",
    "CVE-2021-23134",
    "CVE-2021-28971",
    "CVE-2021-29650",
    "CVE-2021-31829",
    "CVE-2023-1206",
    "CVE-2023-2860",
    "CVE-2023-3358",
    "CVE-2023-3609",
    "CVE-2023-3611",
    "CVE-2023-3776",
    "CVE-2023-3812",
    "CVE-2023-3863",
    "CVE-2023-4004",
    "CVE-2023-4128",
    "CVE-2023-4132",
    "CVE-2023-4206",
    "CVE-2023-4207",
    "CVE-2023-4208",
    "CVE-2023-4387",
    "CVE-2023-4459",
    "CVE-2023-4622",
    "CVE-2023-4921",
    "CVE-2023-35827",
    "CVE-2023-39193",
    "CVE-2023-40283"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2024-0056)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the Linux kernel. An integer overflow in the firmware for some Intel(R) Graphics
    Drivers may allow a privileged user to potentially enable an escalation of privilege via local access. The
    highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2020-12362)

  - A use-after-free flaw was found in usb_sg_cancel in drivers/usb/core/message.c in the USB core subsystem.
    This flaw allows a local attacker with a special user or root privileges to crash the system due to a race
    problem in the scatter-gather cancellation and transfer completion in usb_sg_wait. This vulnerability can
    also lead to a leak of internal kernel information. (CVE-2020-12464)

  - A flaw was found in the Linux kernels implementation of wifi fragmentation handling. An attacker with the
    ability to transmit within the wireless transmission range of an access point can abuse a flaw where
    previous contents of wifi fragments can be unintentionally transmitted to another device. (CVE-2020-24586)

  - A flaw was found in the Linux kernel's WiFi implementation. An attacker within the wireless range can
    abuse a logic flaw in the WiFi implementation by reassembling packets from multiple fragments under
    different keys, treating them as valid. This flaw allows an attacker to send a fragment under an incorrect
    key, treating them as a valid fragment under the new key. The highest threat from this vulnerability is to
    confidentiality. (CVE-2020-24587)

  - A flaw was found in the Linux kernels wifi implementation. An attacker within wireless broadcast range can
    inject custom data into the wireless communication circumventing checks on the data. This can cause the
    frame to pass checks and be considered a valid frame of a different type. (CVE-2020-24588)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2024-0056");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-12362");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-12464");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-24586");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-24587");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-24588");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-25670");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-25671");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-26139");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-26141");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-26143");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-26144");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-26145");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-26147");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-29660");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2020-36158");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-20194");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-23134");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-28971");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-29650");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-31829");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3564");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3573");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3600");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3679");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3732");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-1206");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-2860");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3358");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-35827");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3609");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3611");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3776");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3812");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-3863");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-39193");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4004");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-40283");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4128");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4132");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4206");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4207");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4208");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4387");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4459");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4622");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2023-4921");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36158");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-4921");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-4004");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:bpftool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python3-perf");
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
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.907.g0f83724e5'
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
