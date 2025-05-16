#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184458);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2022-36537");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/20");

  script_name(english:"Potix ZK Framework AuUploader Remote File Disclosure (CVE-2022-36537)");

  script_set_attribute(attribute:"synopsis", value:
"A Java web framework on the remote host is affected by a remote file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Potix ZK Framework detected on the remote host is prior to 8.6.4.2, 9.0.1.3, 9.5.1.4, 9.6.0.2, or 9.6.2.
If is, therefore, affected by a remote file disclosure vulnerability:

  - ZK Framework allows attackers to access sensitive information via a crafted POST request sent to the component
    AuUploader. (CVE-2022-36537)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://tracker.zkoss.org/browse/ZK-5150");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Potix ZK Framework version 8.6.4.2, 9.0.1.3, 9.5.1.4, 9.6.0.2, or 9.6.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36537");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zkoss:zk_framework");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("potix_zk_framework_nix_installed.nbin");
  script_require_keys("installed_sw/Potix ZK Framework");

  exit(0);
}

include('vcf.inc');

var app = vcf::get_app_info(app:'Potix ZK Framework');

var constraints =[
  {'fixed_version':'8.6.4.2'},
  {'min_version':'9.0.0', 'fixed_version':'9.0.1.3'},
  {'min_version':'9.5.0', 'fixed_version':'9.5.1.4'},
  {'min_version':'9.6.0', 'fixed_version':'9.6.0.2'},
  {'min_version':'9.6.1', 'fixed_version':'9.6.2'}
];

vcf::check_version_and_report(
  app_info:app,
  constraints:constraints,
  severity:SECURITY_HOLE
);
