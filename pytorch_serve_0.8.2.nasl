#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184081);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/15");

  script_cve_id("CVE-2023-43654");

  script_name(english:"PyTorch TorchServe < 0.8.2 SSRF");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a machine learning library that is affected by a Server Side Request Forgery vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a torchserve version that is prior to  0.8.2. It is,
therefore, affected by a Server Side Request Forgery vulnerability.  TorchServe default configuration 
lacks proper input validation, enabling third parties to invoke remote HTTP download requests and write 
files to the disk. This issue could be taken advantage of to compromise the integrity of the system and 
sensitive data. This issue is present in versions 0.1.0 to 0.8.1. A remote attacker can exploit this and
load the malicious model of their choice from any URL.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.oligo.security/blog/shelltorch-torchserve-ssrf-vulnerability-cve-2023-43654
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2afbafcc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the TorchServe 0.8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43654");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pytorch:torchserve");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pytorch_torchserve_detect.nbin");
  script_require_keys("installed_sw/TorchServe");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'TorchServe');
vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '0.8.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);