#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.

#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(205460);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2022-2601",
    "CVE-2022-3775",
    "CVE-2023-40547",
    "CVE-2024-29995",
    "CVE-2024-38063",
    "CVE-2024-38106",
    "CVE-2024-38107",
    "CVE-2024-38114",
    "CVE-2024-38115",
    "CVE-2024-38116",
    "CVE-2024-38117",
    "CVE-2024-38118",
    "CVE-2024-38122",
    "CVE-2024-38125",
    "CVE-2024-38126",
    "CVE-2024-38127",
    "CVE-2024-38130",
    "CVE-2024-38131",
    "CVE-2024-38132",
    "CVE-2024-38134",
    "CVE-2024-38140",
    "CVE-2024-38141",
    "CVE-2024-38142",
    "CVE-2024-38143",
    "CVE-2024-38144",
    "CVE-2024-38145",
    "CVE-2024-38146",
    "CVE-2024-38151",
    "CVE-2024-38152",
    "CVE-2024-38153",
    "CVE-2024-38178",
    "CVE-2024-38180",
    "CVE-2024-38193",
    "CVE-2024-38196",
    "CVE-2024-38198",
    "CVE-2024-38199",
    "CVE-2024-38223"
  );
  script_xref(name:"MSKB", value:"5041782");
  script_xref(name:"MSFT", value:"MS24-5041782");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/09/03");
  script_xref(name:"IAVA", value:"2024-A-0487");
  script_xref(name:"IAVA", value:"2024-A-0500-S");
  script_xref(name:"IAVA", value:"2024-A-0499-S");

  script_name(english:"KB5041782: Windows 10 LTS 1507 Security Update (August 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5041782. It is, therefore, affected by multiple vulnerabilities

  - A buffer overflow was found in grub_font_construct_glyph(). A malicious crafted pf2 font can lead to an
    overflow when calculating the max_glyph_size value, allocating a smaller than needed buffer for the glyph,
    this further leads to a buffer overflow and a heap based out-of-bounds write. An attacker may use this
    vulnerability to circumvent the secure boot mechanism. (CVE-2022-2601)

  - A remote code execution vulnerability was found in Shim. The Shim boot support trusts attacker-controlled
    values when parsing an HTTP response. This flaw allows an attacker to craft a specific malicious HTTP
    request, leading to a completely controlled out-of-bounds write primitive and complete system compromise.
    This flaw is only exploitable during the early boot phase, an attacker needs to perform a Man-in-the-
    Middle or compromise the boot server to be able to exploit this vulnerability successfully.
    (CVE-2023-40547)

  - When rendering certain unicode sequences, grub2's font code doesn't proper validate if the informed
    glyph's width and height is constrained within bitmap size. As consequence an attacker can craft an input
    which will lead to a out-of-bounds write into grub2's heap, leading to memory corruption and availability
    issues. Although complex, arbitrary code execution could not be discarded. (CVE-2022-3775)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/help/5041782");
  script_set_attribute(attribute:"solution", value:
"Apply Security Update 5041782");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_10_1507");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS24-08';
kbs = make_list(
  '5041782'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10',
                   os_build:10240,
                   rollup_date:'08_2024',
                   bulletin:bulletin,
                   rollup_kb_list:[5041782])
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
