#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124002);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/03");

  script_cve_id("CVE-2018-5927");
  script_bugtraq_id(107659);
  script_xref(name:"HP", value:"c06242762");
  script_xref(name:"HP", value:"HPSBGN03605");

  script_name(english:"HP Support Assistant < 8.7.50.3 DLL Loading Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an
unspecified DLL loading vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Support Assistant installed on the remote Windows
host is prior to 8.7.50.3. It is, therefore, affected by an
unspecified DLL loading vulnerability. This can allow a local
attacker to load and execute arbitrary code.");
  # https://support.hp.com/us-en/document/c06242762
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?322e31e2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Support Assistant version 8.7.50.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5927");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:support_assistant");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hp_support_assistant_installed.nbin");
  script_require_keys("installed_sw/HP Support Assistant");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"HP Support Assistant");

constraints = [{ "fixed_version" : "8.7.50.3" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
