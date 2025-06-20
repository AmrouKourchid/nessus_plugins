#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154051);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/28");

  script_cve_id(
    "CVE-2021-1971",
    "CVE-2021-3449",
    "CVE-2021-3450",
    "CVE-2021-41355"
  );
  script_xref(name:"IAVA", value:"2021-A-0471-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (October 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security update. They are, therefore, affected by multiple
vulnerabilities:

  - Multiple denial of service (DoS) vulnerabilities exist in Visual Studio. An unauthenticated, remote attacker can 
    exploit these issues to impose a DoS condition on the application. (CVE-2021-1971, CVE-2021-3449, CVE-2021-3450)

  - An information disclosure vulnerability exists in Visual Studio. An unauthenticated, remote attacker can exploit 
    this to disclose potentially sensitive information. (CVE-2021-41355)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.11.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b09b8bb");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.9#16.9.12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be578aea");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.7#16.7.20
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e24738f");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.4#16.4.27
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1505c0a2");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.40
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?68e164a2");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  - Update 15.9.40 for Visual Studio 2017
  - Update 16.4.27 for Visual Studio 2019
  - Update 16.7.20 for Visual Studio 2019
  - Update 16.9.12 for Visual Studio 2019
  - Update 16.11.5 for Visual Studio 2019");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3450");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf_extras_visual_studio.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::visual_studio::get_app_info();

var constraints = [
  {'product': '2017', 'fixed_version': '15.9.28307.1705'},
  {'product': '2019', 'min_version': '16.0', 'fixed_version': '16.4.31728.76'},
  {'product': '2019', 'min_version': '16.5', 'fixed_version': '16.7.31727.298'},
  {'product': '2019', 'min_version': '16.8', 'fixed_version': '16.9.31728.308'},
  {'product': '2019', 'min_version': '16.10', 'fixed_version': '16.11.31729.503'}
];

vcf::visual_studio::check_version_and_report(
  app_info: app_info, 
  constraints: constraints, 
  severity: SECURITY_WARNING
);
