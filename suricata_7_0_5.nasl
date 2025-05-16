#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206344);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/17");

  script_cve_id("CVE-2024-32663", "CVE-2024-32664", "CVE-2024-32867");
  script_xref(name:"IAVB", value:"2024-B-0122-S");

  script_name(english:"Suricata 6.x < 6.0.19 / 7.x < 7.0.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An IDS/IPS solution running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OISF Suricata installed on the remote host is prior to 6.0.19 or 7.x prior to 7.0.5. It is, therefore,
affected by multiple vulnerabilities: 

  - In affected versions, specially crafted traffic or datasets can cause a limited buffer overflow. 
    (CVE-2024-32664)
    
  - In affected versions, a small amount of HTTP/2 traffic can lead to Suricata using a large amount of memory.
    (CVE-2024-32663)
    
  - In affected versions, various problems in handling of fragmentation anomalies can lead to mis-detection of rules 
    and policy. (CVE-2024-32867)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/OISF/suricata/security/advisories/GHSA-9jxm-qw9v-266r
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1c24f6b");
  # https://github.com/OISF/suricata/security/advisories/GHSA-79vh-hpwq-3jh7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a77c0b66");
  # https://github.com/OISF/suricata/security/advisories/GHSA-xvrx-88mv-xcq5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77acbca8");
  script_set_attribute(attribute:"see_also", value:"https://suricata.io/2024/04/23/suricata-7-0-5-and-6-0-19-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Suricata to 6.0.19, 7.0.7 or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-32664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oisf:suricata");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oisf_suricata_win_installed.nbin", "oisf_suricata_nix_installed.nbin");
  script_require_keys("installed_sw/Open Information Security Foundation Suricata");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app: 'Open Information Security Foundation Suricata');

var constraints = [
  {'min_version': '6.0', 'fixed_version': '6.0.19'},
  {'min_version': '7.0', 'fixed_version': '7.0.5'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
