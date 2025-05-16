#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0080. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187332);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/17");

  script_cve_id(
    "CVE-2021-3695",
    "CVE-2021-3696",
    "CVE-2021-3697",
    "CVE-2022-28733",
    "CVE-2022-28734",
    "CVE-2022-28735",
    "CVE-2022-28736",
    "CVE-2022-28737"
  );

  script_name(english:"NewStart CGSL MAIN 6.06 : mokutil Multiple Vulnerabilities (NS-SA-2023-0080)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.06, has mokutil packages installed that are affected by multiple
vulnerabilities:

  - A crafted 16-bit grayscale PNG image may lead to a out-of-bounds write in the heap area. An attacker may
    take advantage of that to cause heap data corruption or eventually arbitrary code execution and circumvent
    secure boot protections. This issue has a high complexity to be exploited as an attacker needs to perform
    some triage over the heap layout to achieve signifcant results, also the values written into the memory
    are repeated three times in a row making difficult to produce valid payloads. This flaw affects grub2
    versions prior grub-2.12. (CVE-2021-3695)

  - A heap out-of-bounds write may heppen during the handling of Huffman tables in the PNG reader. This may
    lead to data corruption in the heap space. Confidentiality, Integrity and Availablity impact may be
    considered Low as it's very complex to an attacker control the encoding and positioning of corrupted
    Huffman entries to achieve results such as arbitrary code execution and/or secure boot circumvention. This
    flaw affects grub2 versions prior grub-2.12. (CVE-2021-3696)

  - A crafted JPEG image may lead the JPEG reader to underflow its data pointer, allowing user-controlled data
    to be written in heap. To a successful to be performed the attacker needs to perform some triage over the
    heap layout and craft an image with a malicious format and payload. This vulnerability can lead to data
    corruption and eventual code execution or secure boot circumvention. This flaw affects grub2 versions
    prior grub-2.12. (CVE-2021-3697)

  - Integer underflow in grub_net_recv_ip4_packets; A malicious crafted IP packet can lead to an integer
    underflow in grub_net_recv_ip4_packets() function on rsm->total_len value. Under certain circumstances the
    total_len value may end up wrapping around to a small integer number which will be used in memory
    allocation. If the attack succeeds in such way, subsequent operations can write past the end of the
    buffer. (CVE-2022-28733)

  - Out-of-bounds write when handling split HTTP headers; When handling split HTTP headers, GRUB2 HTTP code
    accidentally moves its internal data buffer point by one position. This can lead to a out-of-bound write
    further when parsing the HTTP request, writing a NULL byte past the buffer. It's conceivable that an
    attacker controlled set of packets can lead to corruption of the GRUB2's internal memory metadata.
    (CVE-2022-28734)

  - The GRUB2's shim_lock verifier allows non-kernel files to be loaded on shim-powered secure boot systems.
    Allowing such files to be loaded may lead to unverified code and modules to be loaded in GRUB2 breaking
    the secure boot trust-chain. (CVE-2022-28735)

  - There's a use-after-free vulnerability in grub_cmd_chainloader() function; The chainloader command is used
    to boot up operating systems that doesn't support multiboot and do not have direct support from GRUB2.
    When executing chainloader more than once a use-after-free vulnerability is triggered. If an attacker can
    control the GRUB2's memory allocation pattern sensitive data may be exposed and arbitrary code execution
    can be achieved. (CVE-2022-28736)

  - There's a possible overflow in handle_image() when shim tries to load and execute crafted EFI executables;
    The handle_image() function takes into account the SizeOfRawData field from each section to be loaded. An
    attacker can leverage this to perform out-of-bound writes into memory. Arbitrary code execution is not
    discarded in such scenario. (CVE-2022-28737)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/notice/NS-SA-2023-0080");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3695");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3696");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2021-3697");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28733");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28734");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28735");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28736");
  script_set_attribute(attribute:"see_also", value:"https://security.gd-linux.com/info/CVE-2022-28737");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL mokutil packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3696");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28733");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:mokutil");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.06');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.06': [
    'mokutil-0.3.0-11.0.3.zncgsl6_6.1'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mokutil');
}
