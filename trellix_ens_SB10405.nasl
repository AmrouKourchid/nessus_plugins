#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183027);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/16");

  script_cve_id("CVE-2023-3665");
  script_xref(name:"IAVB", value:"2023-B-0079");

  script_name(english:"Trellix Endpoint Security for Windows < 10.7.0 September 2023 Update Code Injection (SB10405)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a code injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"A code injection vulnerability in Trellix ENS 10.7.0 April 2023 release and earlier, allowed a local user to disable
the ENS AMSI component via environment variables, leading to denial of service and or the execution of arbitrary code.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kcm.trellix.com/corporate/index?page=content&id=SB10405");
  # https://docs.trellix.com/bundle/trellix-endpoint-security-10.7.x-release-notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de265897");
  script_set_attribute(attribute:"solution", value:
"Apply the 10.7.0 September 2023 Update or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3665");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:endpoint_security");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trellix:endpoint_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_endpoint_security_installed.nbin");
  script_require_keys("installed_sw/McAfee Endpoint Security Platform", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'McAfee Endpoint Security Platform', win_local:TRUE);

constraints = [
  { 'fixed_version':'10.7.0.6149', 'fixed_display':'ENS 10.7.0 September 2023 Update' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
