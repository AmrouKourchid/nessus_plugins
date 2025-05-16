#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234471);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/23");

  script_cve_id(
    "CVE-2024-47606",
    "CVE-2024-54534",
    "CVE-2025-21587",
    "CVE-2025-30691",
    "CVE-2025-30698"
  );

  script_name(english:"Azul Zulu Java Multiple Vulnerabilities (2025-04-15)");

  script_set_attribute(attribute:"synopsis", value:
"Azul Zulu OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Azul Zulu installed on the remote host is 6 prior to 6.71.0.16 / 7 prior to 7.77.0.14 / 8 prior to
8.85.0.22 / 11 prior to 11.79.20 / 11 prior to 11.79.18 / 17 prior to 17.57.20 / 17 prior to 17.57.18 / 21 prior to
21.41.18 / 24 prior to 24.30.13 / 24 prior to 24.30.12. It is, therefore, affected by multiple vulnerabilities as
referenced in the 2025-04-15 advisory.

  - The issue was addressed with improved memory handling. This issue is fixed in watchOS 11.2, visionOS 2.2,
    tvOS 18.2, macOS Sequoia 15.2, Safari 18.2, iOS 18.2 and iPadOS 18.2. Processing maliciously crafted web
    content may lead to memory corruption. (CVE-2024-54534)

  - GStreamer is a library for constructing graphs of media-handling components. An integer underflow has been
    detected in the function qtdemux_parse_theora_extension within qtdemux.c. The vulnerability occurs due to
    an underflow of the gint size variable, which causes size to hold a large unintended value when cast to an
    unsigned integer. This 32-bit negative value is then cast to a 64-bit unsigned integer
    (0xfffffffffffffffa) in a subsequent call to gst_buffer_new_and_alloc. The function
    gst_buffer_new_allocate then attempts to allocate memory, eventually calling _sysmem_new_block. The
    function _sysmem_new_block adds alignment and header size to the (unsigned) size, causing the overflow of
    the 'slice_size' variable. As a result, only 0x89 bytes are allocated, despite the large input size. When
    the following memcpy call occurs in gst_buffer_fill, the data from the input file will overwrite the
    content of the GstMapInfo info structure. Finally, during the call to gst_memory_unmap, the overwritten
    memory may cause a function pointer hijack, as the mem->allocator->mem_unmap_full function is called with
    a corrupted pointer. This function pointer overwrite could allow an attacker to alter the execution flow
    of the program, leading to arbitrary code execution. This vulnerability is fixed in 1.24.10.
    (CVE-2024-47606)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: JSSE). Supported versions that are affected are Oracle Java SE:8u441,
    8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK:17.0.14, 21.0.6, 24; Oracle GraalVM
    Enterprise Edition:20.3.17 and 21.3.13. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle
    GraalVM Enterprise Edition accessible data as well as unauthorized access to critical data or complete
    access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data.
    Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web
    service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security.
    (CVE-2025-21587)

  - Vulnerability in Oracle Java SE (component: Compiler). Supported versions that are affected are Oracle
    Java SE: 21.0.6, 24; Oracle GraalVM for JDK: 21.0.6 and 24. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Oracle Java SE accessible data as well as unauthorized read access to a subset of Oracle Java SE
    accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g.,
    through a web service which supplies data to the APIs. This vulnerability also applies to Java
    deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets,
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. (CVE-2025-30691)

  - Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of
    Oracle Java SE (component: 2D). Supported versions that are affected are Oracle Java SE: 8u441,
    8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK: 17.0.14, 21.0.6, 24; Oracle GraalVM
    Enterprise Edition: 20.3.17 and 21.3.13. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK,
    Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Java SE,
    Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data and unauthorized ability to
    cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM
    Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2025-30698)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.azul.com/core/release/april-2025/release-notes");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2025 Azul Zulu OpenJDK Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-54534");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-47606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azul:zulu");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zulu_java_nix_installed.nbin", "zulu_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['Azul Zulu Java'];
var app_info = vcf::java::get_app_info(app:app_list);
var package_type = app_info['Reported Code'];

var constraints;

if ('SA' == package_type)
{
constraints = [
    { 'min_version' : '6.0.0', 'fixed_version' : '6.71.0.16', 'fixed_display' : 'Upgrade to a version 6.71.0.16 (SA) and above' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.77.0.14', 'fixed_display' : 'Upgrade to a version 7.77.0.14 (SA) and above' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.85.0.22', 'fixed_display' : 'Upgrade to a version 8.85.0.22 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.79.20', 'fixed_display' : 'Upgrade to a version 11.79.20 (SA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.79.18', 'fixed_display' : 'Upgrade to a version 11.79.18 (SA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.57.20', 'fixed_display' : 'Upgrade to a version 17.57.20 (SA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.57.18', 'fixed_display' : 'Upgrade to a version 17.57.18 (SA) and above' },
    { 'min_version' : '21.0.0', 'fixed_version' : '21.41.18', 'fixed_display' : 'Upgrade to a version 21.41.18 (SA) and above' },
    { 'min_version' : '24.0.0', 'fixed_version' : '24.30.13', 'fixed_display' : 'Upgrade to a version 24.30.13 (SA) and above' },
    { 'min_version' : '24.0.0', 'fixed_version' : '24.30.12', 'fixed_display' : 'Upgrade to a version 24.30.12 (SA) and above' }
  ];
}
else if ('CA' == package_type)
{
  constraints = [
    { 'min_version' : '8.0.0', 'fixed_version' : '8.86.0.25', 'fixed_display' : 'Upgrade to a version 8.86.0.25 (CA) and above' },
    { 'min_version' : '11.0.0', 'fixed_version' : '11.80.21', 'fixed_display' : 'Upgrade to a version 11.80.21 (CA) and above' },
    { 'min_version' : '17.0.0', 'fixed_version' : '17.58.21', 'fixed_display' : 'Upgrade to a version 17.58.21 (CA) and above' },
    { 'min_version' : '21.0.0', 'fixed_version' : '21.42.19', 'fixed_display' : 'Upgrade to a version 21.42.19 (CA) and above' },
    { 'min_version' : '24.0.0', 'fixed_version' : '24.30.11', 'fixed_display' : 'Upgrade to a version 24.30.11 (CA) and above' }
  ];
}

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
