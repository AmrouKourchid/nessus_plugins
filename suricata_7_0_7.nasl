#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214273);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/21");

  script_cve_id(
    "CVE-2024-45795",
    "CVE-2024-45796",
    "CVE-2024-45797",
    "CVE-2024-47187",
    "CVE-2024-47188"
  );
  script_xref(name:"IAVB", value:"2025-B-0005-S");

  script_name(english:"Suricata < 7.0.7 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An IDS/IPS solution running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OISF Suricata installed on the remote host is prior to 6.0.19 or 7.x prior to 7.0.5. It is, therefore,
affected by multiple vulnerabilities: 

  - Missing initialization of the random seed for thash leads to datasets having predictable hash table behavior. This
    can lead to dataset file loading to use excessive time to load, as well as runtime performance issues during traffic 
    handling. (CVE-2024-47187)
    
  - A logic error during fragment reassembly can lead to failed reassembly for valid traffic. An attacker 
    could craft packets to trigger this behavior. (CVE-2024-45796)
    
  - Rules using datasets with the non-functional / unimplemented unset option can trigger an 
    assertion during traffic parsing, leading to denial of service. (CVE-2024-45795)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/OISF/suricata/security/advisories/GHSA-6r8w-fpw6-cp9g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb2a25b4");
  # https://github.com/OISF/suricata/security/advisories/GHSA-mf6r-3xp2-v7xg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b5a419b");
  # https://github.com/OISF/suricata/security/advisories/GHSA-w5xv-6586-jpm7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?780b966f");
  # https://github.com/OISF/suricata/security/advisories/GHSA-64ww-4f6x-863p
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8b7b96d3");
  # https://github.com/OISF/suricata/security/advisories/GHSA-qq5v-qcjx-f872
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1895f45");
  script_set_attribute(attribute:"see_also", value:"https://suricata.io/2024/10/01/suricata-7-0-7-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade Suricata to 7.0.7 or higher.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45795");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-45796");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(193, 330, 617);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/01");
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
  {'fixed_version': '7.0.7'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
