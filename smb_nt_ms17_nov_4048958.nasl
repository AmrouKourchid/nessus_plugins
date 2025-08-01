#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(104554);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/17");

  script_cve_id(
    "CVE-2017-11768",
    "CVE-2017-11788",
    "CVE-2017-11791",
    "CVE-2017-11827",
    "CVE-2017-11831",
    "CVE-2017-11834",
    "CVE-2017-11837",
    "CVE-2017-11838",
    "CVE-2017-11842",
    "CVE-2017-11843",
    "CVE-2017-11846",
    "CVE-2017-11847",
    "CVE-2017-11848",
    "CVE-2017-11849",
    "CVE-2017-11850",
    "CVE-2017-11851",
    "CVE-2017-11853",
    "CVE-2017-11855",
    "CVE-2017-11856",
    "CVE-2017-11858",
    "CVE-2017-11869",
    "CVE-2017-11880"
  );
  script_bugtraq_id(
    101703,
    101705,
    101709,
    101711,
    101715,
    101716,
    101719,
    101721,
    101722,
    101725,
    101729,
    101737,
    101738,
    101740,
    101741,
    101742,
    101751,
    101753,
    101755,
    101762,
    101763,
    101764
  );
  script_xref(name:"MSKB", value:"4048961");
  script_xref(name:"MSKB", value:"4048958");
  script_xref(name:"MSFT", value:"MS17-4048958");
  script_xref(name:"MSFT", value:"MS17-4048961");

  script_name(english:"Windows 8.1 and Windows Server 2012 R2 November 2017 Security Updates");
  script_summary(english:"Checks for rollup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4048961
or cumulative update 4048958. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-11827,
    CVE-2017-11858)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2017-11837, CVE-2017-11838, CVE-2017-11843,
    CVE-2017-11846)

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2017-11855,
    CVE-2017-11856, CVE-2017-11869)

  - An information vulnerability exists when Windows Media
    Player improperly discloses file information. Successful
    exploitation of the vulnerability could allow the
    attacker to test for the presence of files on disk.
    (CVE-2017-11768)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Internet Explorer. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2017-11834)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    (CVE-2017-11880)

  - A Win32k information disclosure vulnerability exists
    when the Windows GDI component improperly discloses
    kernel memory addresses. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2017-11851)

  - An information disclosure vulnerability exists when the
    scripting engine does not properly handle objects in
    memory in Microsoft browsers. An attacker who
    successfully exploited the vulnerability could obtain
    information to further compromise the users system.
    (CVE-2017-11791)

  - An elevation of privilege vulnerability exists when the
    Windows kernel fails to properly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    An attacker could then install programs; view, change,
    or delete data; or create new accounts with full user
    rights.  (CVE-2017-11847)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles page content, which
    could allow an attacker to detect the navigation of the
    user leaving a maliciously crafted page.
    (CVE-2017-11848)

  - An information disclosure vulnerability exists when the
    Windows kernel fails to properly initialize a memory
    address. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2017-11831,
    CVE-2017-11842, CVE-2017-11849, CVE-2017-11853)

  - A denial of service vulnerability exists when Windows
    Search improperly handles objects in memory. An attacker
    who successfully exploited the vulnerability could cause
    a remote denial of service against a system.
    (CVE-2017-11788)

  - An information disclosure vulnerability exists when the
    Microsoft Windows Graphics Component improperly handles
    objects in memory. An attacker who successfully
    exploited the vulnerability could obtain information to
    further compromise the users system.  (CVE-2017-11850)");
  # https://support.microsoft.com/en-us/help/4048961/windows-81-update-kb4048961
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd6d4c6a");
  # https://support.microsoft.com/en-us/help/4048958/windows-81-update-kb4048958
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6b7fa1d0");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4048961 or Cumulative update KB4048958.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11847");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_server_2012:r2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS17-11";
kbs = make_list('4048961', '4048958');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.3",
                   sp:0,
                   rollup_date:"11_2017",
                   bulletin:bulletin,
                   rollup_kb_list:[4048961, 4048958])
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
