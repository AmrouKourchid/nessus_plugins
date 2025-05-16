#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234837);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id(
    "CVE-2024-8176",
    "CVE-2024-40896",
    "CVE-2024-50602",
    "CVE-2024-56171",
    "CVE-2025-24928",
    "CVE-2025-27113",
    "CVE-2025-36625"
  );
  script_xref(name:"IAVA", value:"2025-A-0294");

  script_name(english:"Tenable Nessus < 10.8.4 Multiple Vulnerabilities (TNS-2025-05)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus installed on the remote system is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus application running on the remote host is prior to 10.8.4. It
is, therefore, affected by multiple vulnerabilities as referenced in the TNS-2025-05 advisory.

  - libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a NULL pointer dereference in xmlPatMatch in
    pattern.c. (CVE-2025-27113)

  - In libxml2 2.11 before 2.11.9, 2.12 before 2.12.9, and 2.13 before 2.13.3, the SAX parser can produce
    events for external entities even if custom SAX handlers try to override entity content (by setting
    checked). This makes classic XXE attacks possible. (CVE-2024-40896)

  - An issue was discovered in libexpat before 2.6.4. There is a crash within the XML_ResumeParser function
    because XML_StopParser can stop/suspend an unstarted parser. (CVE-2024-50602)

  - libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a use-after-free in xmlSchemaIDCFillNodeTables and
    xmlSchemaBubbleIDCNodeTables in xmlschemas.c. To exploit this, a crafted XML document must be validated
    against an XML schema with certain identity constraints, or a crafted XML schema must be used.
    (CVE-2024-56171)

  - A stack overflow vulnerability exists in the libexpat library due to the way it handles recursive entity
    expansion in XML documents. When parsing an XML document with deeply nested entity references, libexpat
    can be forced to recurse indefinitely, exhausting the stack space and causing a crash. This issue could
    lead to denial of service (DoS) or, in some cases, exploitable memory corruption, depending on the
    environment and library usage. (CVE-2024-8176)

  - libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a stack-based buffer overflow in xmlSnprintfElements
    in valid.c. To exploit this, DTD validation must occur for an untrusted document or untrusted DTD. NOTE:
    this is similar to CVE-2017-9047. (CVE-2025-24928)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://docs.tenable.com/release-notes/Content/nessus/2025.htm#10.8.4");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/TNS-2025-05");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus 10.8.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27113");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_severity", value:"High");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_detect.nasl", "nessus_installed_win.nbin", "nessus_installed_linux.nbin", "macos_nessus_installed.nbin");
  script_require_keys("installed_sw/Tenable Nessus");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Tenable Nessus');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [ { 'fixed_version' : '10.8.4' } ];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
