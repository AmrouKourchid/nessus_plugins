#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(211696);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/30");

  script_cve_id(
    "CVE-2024-38476",
    "CVE-2024-38477",
    "CVE-2024-39573",
    "CVE-2024-40849",
    "CVE-2024-40854",
    "CVE-2024-40858",
    "CVE-2024-44156",
    "CVE-2024-44159",
    "CVE-2024-44194",
    "CVE-2024-44195",
    "CVE-2024-44196",
    "CVE-2024-44197",
    "CVE-2024-44200",
    "CVE-2024-44201",
    "CVE-2024-44211",
    "CVE-2024-44212",
    "CVE-2024-44213",
    "CVE-2024-44215",
    "CVE-2024-44216",
    "CVE-2024-44218",
    "CVE-2024-44219",
    "CVE-2024-44222",
    "CVE-2024-44223",
    "CVE-2024-44229",
    "CVE-2024-44231",
    "CVE-2024-44232",
    "CVE-2024-44233",
    "CVE-2024-44234",
    "CVE-2024-44236",
    "CVE-2024-44237",
    "CVE-2024-44239",
    "CVE-2024-44240",
    "CVE-2024-44241",
    "CVE-2024-44242",
    "CVE-2024-44244",
    "CVE-2024-44247",
    "CVE-2024-44248",
    "CVE-2024-44250",
    "CVE-2024-44253",
    "CVE-2024-44254",
    "CVE-2024-44255",
    "CVE-2024-44256",
    "CVE-2024-44257",
    "CVE-2024-44259",
    "CVE-2024-44260",
    "CVE-2024-44264",
    "CVE-2024-44265",
    "CVE-2024-44267",
    "CVE-2024-44269",
    "CVE-2024-44270",
    "CVE-2024-44273",
    "CVE-2024-44275",
    "CVE-2024-44277",
    "CVE-2024-44278",
    "CVE-2024-44279",
    "CVE-2024-44280",
    "CVE-2024-44281",
    "CVE-2024-44282",
    "CVE-2024-44283",
    "CVE-2024-44284",
    "CVE-2024-44285",
    "CVE-2024-44286",
    "CVE-2024-44287",
    "CVE-2024-44289",
    "CVE-2024-44290",
    "CVE-2024-44292",
    "CVE-2024-44293",
    "CVE-2024-44294",
    "CVE-2024-44295",
    "CVE-2024-44296",
    "CVE-2024-44297",
    "CVE-2024-44298",
    "CVE-2024-44299",
    "CVE-2024-44301",
    "CVE-2024-44302",
    "CVE-2024-44303",
    "CVE-2024-54471",
    "CVE-2024-54535",
    "CVE-2024-54538"
  );
  script_xref(name:"APPLE-SA", value:"121564");
  script_xref(name:"IAVA", value:"2024-A-0793-S");

  script_name(english:"macOS 15.x < 15.1 Multiple Vulnerabilities (121564)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 15.x prior to 15.1. It is, therefore, affected by
multiple vulnerabilities:

  - The issue was addressed with improved bounds checks. This issue is fixed in iOS 18.1 and iPadOS 18.1. An
    attacker may be able to cause unexpected system termination or arbitrary code execution in DCP firmware.
    (CVE-2024-44241, CVE-2024-44242, CVE-2024-44299)

  - Vulnerability in core of Apache HTTP Server 2.4.59 and earlier are vulnerably to information disclosure,
    SSRF or local script execution via backend applications whose response headers are malicious or
    exploitable. Users are recommended to upgrade to version 2.4.60, which fixes this issue. (CVE-2024-38476)

  - null pointer dereference in mod_proxy in Apache HTTP Server 2.4.59 and earlier allows an attacker to crash
    the server via a malicious request. Users are recommended to upgrade to version 2.4.60, which fixes this
    issue. (CVE-2024-38477)

  - Potential SSRF in mod_rewrite in Apache HTTP Server 2.4.59 and earlier allows an attacker to cause unsafe
    RewriteRules to unexpectedly setup URL's to be handled by mod_proxy. Users are recommended to upgrade to
    version 2.4.60, which fixes this issue. (CVE-2024-39573)

  - A memory initialization issue was addressed with improved memory handling. This issue is fixed in iOS 18.1
    and iPadOS 18.1, iOS 17.7.1 and iPadOS 17.7.1, macOS Sonoma 14.7.1, macOS Ventura 13.7.1. An app may be
    able to cause unexpected system termination. (CVE-2024-40854)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/121564");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 15.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-44299");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:15.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '15.1.0', 'min_version' : '15.0', 'fixed_display' : 'macOS Sequoia 15.1' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
