#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202310-02.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(182438);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id(
    "CVE-2021-1052",
    "CVE-2021-1053",
    "CVE-2021-1056",
    "CVE-2021-1090",
    "CVE-2021-1093",
    "CVE-2021-1094",
    "CVE-2021-1095",
    "CVE-2022-28181",
    "CVE-2022-28183",
    "CVE-2022-28184",
    "CVE-2022-28185",
    "CVE-2022-31607",
    "CVE-2022-31608",
    "CVE-2022-31615",
    "CVE-2022-34666",
    "CVE-2022-34670",
    "CVE-2022-34673",
    "CVE-2022-34674",
    "CVE-2022-34676",
    "CVE-2022-34677",
    "CVE-2022-34678",
    "CVE-2022-34679",
    "CVE-2022-34680",
    "CVE-2022-34682",
    "CVE-2022-34684",
    "CVE-2022-42254",
    "CVE-2022-42255",
    "CVE-2022-42256",
    "CVE-2022-42257",
    "CVE-2022-42258",
    "CVE-2022-42259",
    "CVE-2022-42260",
    "CVE-2022-42261",
    "CVE-2022-42263",
    "CVE-2022-42264",
    "CVE-2022-42265",
    "CVE-2023-0180",
    "CVE-2023-0181",
    "CVE-2023-0183",
    "CVE-2023-0184",
    "CVE-2023-0185",
    "CVE-2023-0187",
    "CVE-2023-0188",
    "CVE-2023-0189",
    "CVE-2023-0190",
    "CVE-2023-0191",
    "CVE-2023-0194",
    "CVE-2023-0195",
    "CVE-2023-0198",
    "CVE-2023-0199"
  );

  script_name(english:"GLSA-202310-02 : NVIDIA Drivers: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202310-02 (NVIDIA Drivers: Multiple Vulnerabilities)

  - NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel mode
    layer (nvlddmkm.sys) handler for DxgkDdiEscape or IOCTL in which user-mode clients can access legacy
    privileged APIs, which may lead to denial of service, escalation of privileges, and information
    disclosure. (CVE-2021-1052)

  - NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel mode
    layer (nvlddmkm.sys) handler for DxgkDdiEscape or IOCTL in which improper validation of a user pointer may
    lead to denial of service. (CVE-2021-1053)

  - NVIDIA GPU Display Driver for Linux, all versions, contains a vulnerability in the kernel mode layer
    (nvidia.ko) in which it does not completely honor operating system file system permissions to provide GPU
    device-level isolation, which may lead to denial of service or information disclosure. (CVE-2021-1056)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer
    (nvlddmkm.sys) handler for control calls where the software reads or writes to a buffer by using an index
    or pointer that references a memory location after the end of the buffer, which may lead to data tampering
    or denial of service. (CVE-2021-1090)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in firmware where the driver
    contains an assert() or similar statement that can be triggered by an attacker, which leads to an
    application exit or other behavior that is more severe than necessary, and may lead to denial of service
    or system crash. (CVE-2021-1093)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer
    (nvlddmkm.sys) handler for DxgkDdiEscape where an out of bounds array access may lead to denial of service
    or information disclosure. (CVE-2021-1094)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer
    (nvlddmkm.sys) handlers for all control calls with embedded parameters where dereferencing an untrusted
    pointer may lead to denial of service. (CVE-2021-1095)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where
    an unprivileged regular user on the network can cause an out-of-bounds write through a specially crafted
    shader, which may lead to code execution, denial of service, escalation of privileges, information
    disclosure, and data tampering. The scope of the impact may extend to other components. (CVE-2022-28181)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where
    an unprivileged regular user can cause an out-of-bounds read, which may lead to denial of service and
    information disclosure. (CVE-2022-28183)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer
    (nvlddmkm.sys) handler for DxgkDdiEscape, where an unprivileged regular user can access administrator-
    privileged registers, which may lead to denial of service, information disclosure, and data tampering.
    (CVE-2022-28184)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the ECC layer, where an
    unprivileged regular user can cause an out-of-bounds write, which may lead to denial of service and data
    tampering. (CVE-2022-28185)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where a
    local user with basic capabilities can cause improper input validation, which may lead to denial of
    service, escalation of privileges, data tampering, and limited information disclosure. (CVE-2022-31607)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in an optional D-Bus configuration file,
    where a local user with basic capabilities can impact protected D-Bus endpoints, which may lead to code
    execution, denial of service, escalation of privileges, information disclosure, and data tampering.
    (CVE-2022-31608)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where a local user
    with basic capabilities can cause a null-pointer dereference, which may lead to denial of service.
    (CVE-2022-31615)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where a
    local user with basic capabilities can cause a null-pointer dereference, which may lead to denial of
    service. (CVE-2022-34666)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    unprivileged regular user can cause truncation errors when casting a primitive to a primitive of smaller
    size causes data to be lost in the conversion, which may lead to denial of service or information
    disclosure. (CVE-2022-34670)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an out-of-bounds array access may lead to denial of service, information disclosure, or data tampering.
    (CVE-2022-34673, CVE-2022-42255)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where a
    helper function maps more physical pages than were requested, which may lead to undefined behavior or an
    information leak. (CVE-2022-34674)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    out-of-bounds read may lead to denial of service, information disclosure, or data tampering.
    (CVE-2022-34676)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    unprivileged regular user can cause an integer to be truncated, which may lead to denial of service or
    data tampering. (CVE-2022-34677)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer, where
    an unprivileged user can cause a null-pointer dereference, which may lead to denial of service.
    (CVE-2022-34678)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    unhandled return value can lead to a null-pointer dereference, which may lead to denial of service.
    (CVE-2022-34679)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    integer truncation can lead to an out-of-bounds read, which may lead to denial of service.
    (CVE-2022-34680)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an
    unprivileged regular user can cause a null-pointer dereference, which may lead to denial of service.
    (CVE-2022-34682)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an off-by-one error may lead to data tampering or information disclosure. (CVE-2022-34684)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an out-of-bounds array access may lead to denial of service, data tampering, or information disclosure.
    (CVE-2022-42254)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow in index validation may lead to denial of service, information disclosure, or data
    tampering. (CVE-2022-42256)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow may lead to information disclosure, data tampering or denial of service.
    (CVE-2022-42257)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow may lead to denial of service, data tampering, or information disclosure.
    (CVE-2022-42258)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow may lead to denial of service. (CVE-2022-42259)

  - NVIDIA vGPU Display Driver for Linux guest contains a vulnerability in a D-Bus configuration file, where
    an unauthorized user in the guest VM can impact protected D-Bus endpoints, which may lead to code
    execution, denial of service, escalation of privileges, information disclosure, or data tampering.
    (CVE-2022-42260)

  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where an input
    index is not validated, which may lead to buffer overrun, which in turn may cause data tampering,
    information disclosure, or denial of service. (CVE-2022-42261)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    Integer overflow may lead to denial of service or information disclosure. (CVE-2022-42263)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an
    unprivileged regular user can cause the use of an out-of-range pointer offset, which may lead to data
    tampering, data loss, information disclosure, or denial of service. (CVE-2022-42264)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where
    an integer overflow may lead to information disclosure or data tampering. (CVE-2022-42265)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in a kernel mode layer handler, which may
    lead to denial of service or information disclosure. (CVE-2023-0180)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in a kernel mode layer handler,
    where memory permissions are not correctly checked, which may lead to denial of service and data
    tampering. (CVE-2023-0181)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer where an out-of-
    bounds write can lead to denial of service and data tampering. (CVE-2023-0183)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer handler
    which may lead to denial of service, escalation of privileges, information disclosure, and data tampering.
    (CVE-2023-0184)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where sign
    conversion issuescasting an unsigned primitive to signed may lead to denial of service or information
    disclosure. (CVE-2023-0185)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer handler,
    where an out-of-bounds read can lead to denial of service. (CVE-2023-0187)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer handler,
    where an unprivileged user can cause improper restriction of operations within the bounds of a memory
    buffer cause an out-of-bounds read, which may lead to denial of service. (CVE-2023-0188)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler which may
    lead to code execution, denial of service, escalation of privileges, information disclosure, and data
    tampering. (CVE-2023-0189)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where a NULL
    pointer dereference may lead to denial of service. (CVE-2023-0190)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer handler,
    where an out-of-bounds access may lead to denial of service or data tampering. (CVE-2023-0191)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer driver,
    where an invalid display configuration may lead to denial of service. (CVE-2023-0194)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer driver
    nvlddmkm.sys, where an can cause CWE-1284, which may lead to hypothetical Information leak of unimportant
    data such as local variable data of the driver (CVE-2023-0195)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where improper
    restriction of operations within the bounds of a memory buffer can lead to denial of service, information
    disclosure, and data tampering. (CVE-2023-0198)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer handler,
    where an out-of-bounds write can lead to denial of service and data tampering. (CVE-2023-0199)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202310-02");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=764512");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=784596");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=803389");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=832867");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=845063");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=866527");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=881341");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=884045");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=903614");
  script_set_attribute(attribute:"solution", value:
"All NVIDIA Drivers 470 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-drivers/nvidia-drivers-470.182.03:0/470
        
All NVIDIA Drivers 515 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-drivers/nvidia-drivers-515.105.01:0/515
        
All NVIDIA Drivers 525 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-drivers/nvidia-drivers-525.105.17:0/525
        
All NVIDIA Drivers 530 users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=x11-drivers/nvidia-drivers-530.41.03:0/530");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1052");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28181");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:nvidia-drivers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'x11-drivers/nvidia-drivers',
    'unaffected' : make_list("ge 470.182.03", "lt 470.0.0"),
    'vulnerable' : make_list("lt 470.182.03")
  },
  {
    'name' : 'x11-drivers/nvidia-drivers',
    'unaffected' : make_list("ge 515.105.01", "lt 515.0.0"),
    'vulnerable' : make_list("lt 515.105.01")
  },
  {
    'name' : 'x11-drivers/nvidia-drivers',
    'unaffected' : make_list("ge 525.105.17", "lt 525.0.0"),
    'vulnerable' : make_list("lt 525.105.17")
  },
  {
    'name' : 'x11-drivers/nvidia-drivers',
    'unaffected' : make_list("ge 530.41.03", "lt 530.0.0"),
    'vulnerable' : make_list("lt 530.41.03")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'NVIDIA Drivers');
}
