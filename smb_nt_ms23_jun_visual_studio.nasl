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
  script_id(177249);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/10");

  script_cve_id(
    "CVE-2023-21808",
    "CVE-2023-21815",
    "CVE-2023-23381",
    "CVE-2023-24895",
    "CVE-2023-24897",
    "CVE-2023-24936",
    "CVE-2023-25652",
    "CVE-2023-25815",
    "CVE-2023-27909",
    "CVE-2023-27910",
    "CVE-2023-27911",
    "CVE-2023-29007",
    "CVE-2023-29011",
    "CVE-2023-29012",
    "CVE-2023-29331",
    "CVE-2023-33032",
    "CVE-2023-33126",
    "CVE-2023-33128",
    "CVE-2023-33135",
    "CVE-2023-33139"
  );
  script_xref(name:"MSKB", value:"5025792");
  script_xref(name:"MSKB", value:"5026454");
  script_xref(name:"MSKB", value:"5026455");
  script_xref(name:"MSKB", value:"5026610");
  script_xref(name:"MSFT", value:"MS23-5025792");
  script_xref(name:"MSFT", value:"MS23-5026454");
  script_xref(name:"MSFT", value:"MS23-5026455");
  script_xref(name:"MSFT", value:"MS23-5026610");
  script_xref(name:"IAVA", value:"2023-A-0293-S");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability in the MSDIA SDK where corrupted PDBs can cause heap overflow, 
    leading to a crash or remote code execution. (CVE-2023-24897)

  - A remote code execution vulnerability where specially crafted input to git apply -reject can lead to 
    controlled content writes at arbitrary locations. (CVE-2023-25652)

  - A spoofing vulnerability where Github localization messages refer to a hard-coded path instead of 
    respecting the runtime prefix that leads to out-of-bound memory writes and crashes. (CVE-2023-25815)

  - An Out-Of-Bounds Write Vulnerability in Autodesk FBX SDK version 2020 or prior may lead to code 
    execution through maliciously crafted FBX files or information disclosure. (CVE-2023-27909)

  - An information disclosure vulnerability where a user may be tricked into opening a malicious 
    FBX file. This may exploit a stack buffer overflow (CVE-2023-27910) or heap buffer overflow 
    (CVE-2023-27911) vulnerability in Autodesk FBX SDK 2020 or prior which may lead to remote code
    execution. 

  - A remote code execution vulnerability where a configuration file containing a logic error results
    in arbitrary configuration injection. (CVE-2023-29007)

  - A remote code execution vulnerability where the Git for Windows executable responsible for 
    implementing a SOCKS5 proxy is susceptible to picking up an untrusted configuration on multi-user 
    machines. (CVE-2023-29011)

  - A remote code execution vulnerability where the Git for Windows Git CMD program incorrectly 
    searches for a program upon startup, leading to silent arbitrary code execution. (CVE-2023-29012)

  - A remote code execution vulnerability in the .NET SDK during tool restore which can lead to an 
    elevation of privilege. (CVE-2023-33135)

  - An information disclosure vulnerability by the obj file parser in Visual Studio. (CVE-2023-33139)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes#17.6.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dddbae5d");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.4#1748--visual-studio-2022-version-1748
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a49726ef");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.2#17216--visual-studio-2022-version-17216
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9a1613a0");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2022/release-notes-v17.0#17022--visual-studio-2022-version-17022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d05a264");
  # https://learn.microsoft.com/en-us/visualstudio/releases/2019/release-notes#release-notes-icon-visual-studio-2019-version-161127
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c46148fb");
  # https://learn.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.55
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bdcff516");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5026454");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5025792");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5026455");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5026610");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
        - Patch for the Update 5 for Visual Studio 2013
        - Patch for the Update 3 for Visual Studio 2015
        - Update 15.9.55 for Visual Studio 2017
        - Update 16.11.27 for Visual Studio 2019
        - Update 17.0.22 for Visual Studio 2022
        - Update 17.2.16 for Visual Studio 2022
        - Update 17.4.8 for Visual Studio 2022
        - Update 17.6.3 for Visual Studio 2022");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25652");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-33032");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft Visual Studio", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_visual_studio.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');

var port = kb_smb_transport();
var appname = 'Microsoft Visual Studio';
var installs = get_installs(app_name:appname, exit_if_not_found:TRUE);
var report = '';
var fversion, file, fver, kb_file, kb_files, version, path, prod, fix, install;

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['product_version'];

  if (version =~ '^14\\.0\\.')
  {
    # KB5025792 \Team Tools\Dynamic Code Coverage Tools\covrun32.dll and (if any)
    # Team Tools\Dynamic Code Coverage Tools\amd64\covrun64.dll should be 14.0.27555.0
    fix = '14.0.27555.0';
    kb_files = make_list('Team Tools\\Dynamic Code Coverage Tools\\covrun32.dll',
                         'Team Tools\\Dynamic Code Coverage Tools\\amd64\\covrun64.dll');
    foreach kb_file (kb_files)
    {
      file = hotfix_append_path(path:path, value:kb_file);
      fver = hotfix_get_fversion(path:file);

      if (fver['error'] == HCF_OK && !empty_or_null(fver['value']))
      {
        fversion = join(sep:'.', fver['value']);
        if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
        {
          report +=
            '\n  Path              : ' + file +
            '\n  Installed version : ' + fversion +
            '\n  Fixed version     : ' + fix +
            '\n';
          break;
        }
      }
    }

    # KB5026455 \Common7\IDE\Extensions\Microsoft\VsGraphics\VsGraphics.exe and 
    # \Common7\IDE\Extensions\Microsoft\VsGraphics\VsGraphicsCore.dll should be 14.0.27554.0
    fix = '14.0.27554.0';
    kb_files = make_list('Common7\\IDE\\Extensions\\Microsoft\\VsGraphics\\VsGraphics.exe',
                         'Common7\\IDE\\Extensions\\Microsoft\\VsGraphics\\VsGraphicsCore.dll');
    foreach kb_file (kb_files)
    {
      file = hotfix_append_path(path:path, value:kb_file);
      fver = hotfix_get_fversion(path:file);

      if (fver['error'] == HCF_OK && !empty_or_null(fver['value']))
      {
        fversion = join(sep:'.', fver['value']);
        if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
        {
          report +=
            '\n  Path              : ' + file +
            '\n  Installed version : ' + fversion +
            '\n  Fixed version     : ' + fix +
            '\n';
          break;
        }
      }
    }
  }
  else if (version =~ '^12\\.0\\.')
  {
    # KB5026610 \Common7\IDE\msdia120.dll and 
    # \Team Tools\Dynamic Code Coverage Tools\msdia120.dll should be 12.0.40700.0
    fix = '12.0.40700.0';
    kb_files = make_list('Common7\\IDE\\msdia120.dll',
                         'Team Tools\\Dynamic Code Coverage Tools\\msdia120.dll');
    foreach kb_file (kb_files)
    {
      file = hotfix_append_path(path:path, value:kb_file);
      fver = hotfix_get_fversion(path:file);

      if (fver['error'] == HCF_OK && !empty_or_null(fver['value']))
      {
        fversion = join(sep:'.', fver['value']);
        if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
        {
          report +=
            '\n  Path              : ' + file +
            '\n  Installed version : ' + fversion +
            '\n  Fixed version     : ' + fix +
            '\n';
          break;
        }
      }
    }

    # KB5026454 \Common7\IDE\Extensions\Microsoft\VsGraphics\VsGraphics.exe and 
    # \Common7\IDE\Extensions\Microsoft\VsGraphics\VsGraphicsCore.dll should be 12.0.40702.0
    fix = '12.0.40702.0';
    kb_files = make_list('Common7\\IDE\\Extensions\\Microsoft\\VsGraphics\\VsGraphics.exe',
                         'Common7\\IDE\\Extensions\\Microsoft\\VsGraphics\\VsGraphicsCore.dll');
    foreach kb_file (kb_files)
    {
      file = hotfix_append_path(path:path, value:kb_file);
      fver = hotfix_get_fversion(path:file);

      if (fver['error'] == HCF_OK && !empty_or_null(fver['value']))
      {
        fversion = join(sep:'.', fver['value']);
        if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
        {
          report +=
            '\n  Path              : ' + file +
            '\n  Installed version : ' + fversion +
            '\n  Fixed version     : ' + fix +
            '\n';
          break;
        }
      }
    }
  }
  else if (prod == '2017')
  {
    fix = '15.9.33801.237';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + '15.9.33801.237 (15.9.55)' +
        '\n';
    }
  }
  else if (prod == '2019')
  {
    fix = '16.11.33801.447';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + '16.11.33801.447 (16.11.27)' +
        '\n';
    }
  }
  else if (prod == '2022' && version =~ "^17\.0\.")
  {
    fix = '17.0.33801.228';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + '17.0.33801.228 (17.0.22)' +
        '\n';
    }
  }
  else if (prod == '2022' && version =~ "^17\.[1-2]\.")
  {
    fix = '17.2.33801.349';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + '17.2.33801.349 (17.2.16)' +
        '\n';
    }
  }
  else if (prod == '2022' && version =~ "^17\.[3-4]\.")
  {
    fix = '17.4.33801.306';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + '17.4.33801.306 (17.4.8)' +
        '\n';
    }
  }
  else if (prod == '2022' && version =~ "^17\.[5-6]\.")
  {
    fix = '17.6.33801.468';
    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + '17.6.33801.468 (17.6.3)' +
        '\n';
    }
  }
}

hotfix_check_fversion_end();

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname, version);

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
