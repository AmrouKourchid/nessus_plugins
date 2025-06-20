#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(147231);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2021-1640",
    "CVE-2021-24107",
    "CVE-2021-26411",
    "CVE-2021-26861",
    "CVE-2021-26862",
    "CVE-2021-26869",
    "CVE-2021-26872",
    "CVE-2021-26873",
    "CVE-2021-26875",
    "CVE-2021-26877",
    "CVE-2021-26878",
    "CVE-2021-26881",
    "CVE-2021-26882",
    "CVE-2021-26893",
    "CVE-2021-26894",
    "CVE-2021-26895",
    "CVE-2021-26896",
    "CVE-2021-26897",
    "CVE-2021-26898",
    "CVE-2021-26899",
    "CVE-2021-26901",
    "CVE-2021-27063",
    "CVE-2021-27077"
  );
  script_xref(name:"MSKB", value:"5000841");
  script_xref(name:"MSKB", value:"5000851");
  script_xref(name:"MSFT", value:"MS21-5000841");
  script_xref(name:"MSFT", value:"MS21-5000851");
  script_xref(name:"IAVA", value:"2021-A-0130-S");
  script_xref(name:"IAVA", value:"2021-A-0134-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0015");

  script_name(english:"KB5000851: Windows 7 and Windows Server 2008 R2 March 2021 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5000851
or cumulative update 5000841. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-26861,
    CVE-2021-26877, CVE-2021-26881, CVE-2021-26893,
    CVE-2021-26894, CVE-2021-26895, CVE-2021-26897)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2021-24107, CVE-2021-26869)

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2021-1640, CVE-2021-26862, CVE-2021-26872,
    CVE-2021-26873, CVE-2021-26875, CVE-2021-26878,
    CVE-2021-26882, CVE-2021-26898, CVE-2021-26899,
    CVE-2021-26901, CVE-2021-27077)

  - An memory corruption vulnerability exists. An attacker
    can exploit this to corrupt the memory and cause
    unexpected behaviors within the system/application.
    (CVE-2021-26411)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2021-26896,
    CVE-2021-27063)");
  # https://support.microsoft.com/en-us/topic/march-9-2021-kb5000851-security-only-update-9e198918-a6d6-46d3-8cfb-bd2b1e2ecb99
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cce9359");
  # https://support.microsoft.com/en-us/topic/march-9-2021-kb5000841-monthly-rollup-3a2cced1-f436-40c3-a8a1-645f86759088
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c5851d4");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB5000851 or Cumulative Update KB5000841.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2008:r2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_7");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS21-03';
kbs = make_list(
  '5000841',
  '5000851'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.1', 
                   sp:1,
                   rollup_date:'03_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5000841, 5000851])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
