#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214272);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_cve_id(
    "CVE-2024-55605",
    "CVE-2024-55626",
    "CVE-2024-55627",
    "CVE-2024-55628",
    "CVE-2024-55629"
  );
  script_xref(name:"IAVB", value:"2025-B-0005-S");

  script_name(english:"Suricata < 7.0.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An IDS/IPS solution running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OISF Suricata installed on the remote host is prior to 6.0.19 or 7.x prior to 7.0.5. It is, therefore,
affected by multiple vulnerabilities: 

  - A large input buffer to one of the following transforms can lead to a stack overflow causing Suricata to 
    crash in the following transforms: to_lowercase, to_uppercase, strip_whitespace, compress_whitespace, dotprefix,
    header_lowercase, strip_pseudo_headers, url_decode, xor (CVE-2024-55605)
    
  - A large BPF filter file provided to Suricata at startup can lead to a buffer overflow at Suricata startup. 
    (CVE-2024-55626)
    
  - A specially crafted TCP stream can lead to a very large buffer overflow while being zero-filled during 
    initialization with memset due to an unsigned integer underflow. (CVE-2024-55627)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/OISF/suricata/security/advisories/GHSA-x2hr-33vp-w289
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16b5d78a");
  # https://github.com/OISF/suricata/security/advisories/GHSA-wmg4-jqx5-4h9v
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccb23e05");
  # https://github.com/OISF/suricata/security/advisories/GHSA-h2mv-7gg8-8x7v
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77fb895c");
  # https://github.com/OISF/suricata/security/advisories/GHSA-96w4-jqwf-qx2j
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6251896c");
  # https://github.com/OISF/suricata/security/advisories/GHSA-69wr-vhwg-84h2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9dbccb25");
  script_set_attribute(attribute:"see_also", value:"https://suricata.io/2024/12/12/suricata-7-0-8-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Suricata to 7.0.8 or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-55629");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 191, 405, 437, 779, 680);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oisf:suricata");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oisf_suricata_win_installed.nbin", "oisf_suricata_nix_installed.nbin");
  script_require_keys("installed_sw/Open Information Security Foundation Suricata");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app: 'Open Information Security Foundation Suricata');

var constraints = [
  {'fixed_version': '7.0.8'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
