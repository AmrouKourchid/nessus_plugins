#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235720);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/12");

  script_cve_id(
    "CVE-2024-8176",
    "CVE-2025-24142",
    "CVE-2025-24144",
    "CVE-2025-24155",
    "CVE-2025-24258",
    "CVE-2025-24274",
    "CVE-2025-30440",
    "CVE-2025-30442",
    "CVE-2025-30448",
    "CVE-2025-30453",
    "CVE-2025-31196",
    "CVE-2025-31208",
    "CVE-2025-31209",
    "CVE-2025-31213",
    "CVE-2025-31219",
    "CVE-2025-31220",
    "CVE-2025-31221",
    "CVE-2025-31222",
    "CVE-2025-31224",
    "CVE-2025-31232",
    "CVE-2025-31233",
    "CVE-2025-31235",
    "CVE-2025-31237",
    "CVE-2025-31239",
    "CVE-2025-31240",
    "CVE-2025-31241",
    "CVE-2025-31242",
    "CVE-2025-31245",
    "CVE-2025-31247",
    "CVE-2025-31251"
  );
  script_xref(name:"APPLE-SA", value:"122718");

  script_name(english:"macOS 13.x < 13.7.6 Multiple Vulnerabilities (122718)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of macOS / Mac OS X that is 13.x prior to 13.7.6. It is, therefore, affected by
multiple vulnerabilities:

  - A stack overflow vulnerability exists in the libexpat library due to the way it handles recursive entity
    expansion in XML documents. When parsing an XML document with deeply nested entity references, libexpat
    can be forced to recurse indefinitely, exhausting the stack space and causing a crash. This issue could
    lead to denial of service (DoS) or, in some cases, exploitable memory corruption, depending on the
    environment and library usage. (CVE-2024-8176)

Note that Nessus has not tested for these issues but has instead relied only on the operating system's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/122718");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS 13.7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-8176");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x:13.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos:13.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'fixed_version' : '13.7.6', 'min_version' : '13.0', 'fixed_display' : 'macOS Ventura 13.7.6' }
];

vcf::apple::macos::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
