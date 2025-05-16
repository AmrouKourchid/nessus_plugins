#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233569);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/02");

  script_cve_id(
    "CVE-2024-40864",
    "CVE-2024-54533",
    "CVE-2024-56171",
    "CVE-2024-9681",
    "CVE-2025-24085",
    "CVE-2025-24126",
    "CVE-2025-24129",
    "CVE-2025-24131",
    "CVE-2025-24139",
    "CVE-2025-24148",
    "CVE-2025-24157",
    "CVE-2025-24164",
    "CVE-2025-24170",
    "CVE-2025-24172",
    "CVE-2025-24173",
    "CVE-2025-24177",
    "CVE-2025-24178",
    "CVE-2025-24179",
    "CVE-2025-24181",
    "CVE-2025-24190",
    "CVE-2025-24195",
    "CVE-2025-24198",
    "CVE-2025-24199",
    "CVE-2025-24203",
    "CVE-2025-24205",
    "CVE-2025-24206",
    "CVE-2025-24207",
    "CVE-2025-24210",
    "CVE-2025-24211",
    "CVE-2025-24212",
    "CVE-2025-24215",
    "CVE-2025-24228",
    "CVE-2025-24229",
    "CVE-2025-24230",
    "CVE-2025-24231",
    "CVE-2025-24232",
    "CVE-2025-24233",
    "CVE-2025-24234",
    "CVE-2025-24235",
    "CVE-2025-24237",
    "CVE-2025-24238",
    "CVE-2025-24240",
    "CVE-2025-24241",
    "CVE-2025-24243",
    "CVE-2025-24244",
    "CVE-2025-24246",
    "CVE-2025-24247",
    "CVE-2025-24249",
    "CVE-2025-24250",
    "CVE-2025-24251",
    "CVE-2025-24252",
    "CVE-2025-24253",
    "CVE-2025-24254",
    "CVE-2025-24255",
    "CVE-2025-24256",
    "CVE-2025-24259",
    "CVE-2025-24260",
    "CVE-2025-24261",
    "CVE-2025-24265",
    "CVE-2025-24266",
    "CVE-2025-24267",
    "CVE-2025-24270",
    "CVE-2025-24271",
    "CVE-2025-24272",
    "CVE-2025-24273",
    "CVE-2025-24276",
    "CVE-2025-24277",
    "CVE-2025-24278",
    "CVE-2025-24279",
    "CVE-2025-27113",
    "CVE-2025-30424",
    "CVE-2025-30429",
    "CVE-2025-30432",
    "CVE-2025-30433",
    "CVE-2025-30438",
    "CVE-2025-30443",
    "CVE-2025-30444",
    "CVE-2025-30445",
    "CVE-2025-30446",
    "CVE-2025-30447",
    "CVE-2025-30449",
    "CVE-2025-30450",
    "CVE-2025-30452",
    "CVE-2025-30456",
    "CVE-2025-30457",
    "CVE-2025-30460",
    "CVE-2025-30462",
    "CVE-2025-30464",
    "CVE-2025-30465",
    "CVE-2025-30470",
    "CVE-2025-30471",
    "CVE-2025-31182",
    "CVE-2025-31187",
    "CVE-2025-31188",
    "CVE-2025-31191",
    "CVE-2025-31194",
    "CVE-2025-31197"
  );
  script_xref(name:"APPLE-SA", value:"122375");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/19");
  script_xref(name:"IAVA", value:"2025-A-0222");

  script_name(english:"macOS 13.x < 13.7.5 Multiple Vulnerabilities (122375)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.7.5. It is, therefore, affected by
multiple vulnerabilities:

  - A use after free issue was addressed with improved memory management. This issue is fixed in visionOS 2.3,
    iOS 18.3 and iPadOS 18.3, macOS Sequoia 15.3, watchOS 11.3, tvOS 18.3. A malicious application may be able
    to elevate privileges. Apple is aware of a report that this issue may have been actively exploited against
    versions of iOS before iOS 17.2. (CVE-2025-24085)

  - The issue was addressed with improved handling of protocols. This issue is fixed in macOS Ventura 13.7.5,
    macOS Sonoma 14.7.5. An attacker in a privileged network position can track a user's activity.
    (CVE-2024-40864)

  - A permissions issue was addressed with additional sandbox restrictions. This issue is fixed in macOS
    Ventura 13.7.5, macOS Sonoma 14.7.5. An app may be able to access sensitive user data. (CVE-2024-54533)

  - libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a use-after-free in xmlSchemaIDCFillNodeTables and
    xmlSchemaBubbleIDCNodeTables in xmlschemas.c. To exploit this, a crafted XML document must be validated
    against an XML schema with certain identity constraints, or a crafted XML schema must be used.
    (CVE-2024-56171)

  - When curl is asked to use HSTS, the expiry time for a subdomain might overwrite a parent domain's cache
    entry, making it end sooner or later than otherwise intended. This affects curl using applications that
    enable HSTS and use URLs with the insecure `HTTP://` scheme and perform transfers with hosts like
    `x.example.com` as well as `example.com` where the first host is a subdomain of the second host. (The HSTS
    cache either needs to have been populated manually or there needs to have been previous HTTPS accesses
    done as the cache needs to have entries for the domains involved to trigger this problem.) When
    `x.example.com` responds with `Strict-Transport-Security:` headers, this bug can make the subdomain's
    expiry timeout *bleed over* and get set for the parent domain `example.com` in curl's HSTS cache. The
    result of a triggered bug is that HTTP accesses to `example.com` get converted to HTTPS for a different
    period of time than what was asked for by the origin server. If `example.com` for example stops supporting
    HTTPS at its expiry time, curl might then fail to access `http://example.com` until the (wrongly set)
    timeout expires. This bug can also expire the parent's entry *earlier*, thus making curl inadvertently
    switch back to insecure HTTP earlier than otherwise intended. (CVE-2024-9681)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/122375");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.7.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:13.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/local_checks_enabled", "Host/MacOSX/packages/boms");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_apple.inc');

var app_info = vcf::apple::macos::get_app_info();

var constraints = [
  { 'fixed_version' : '13.7.5', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.7.5' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
