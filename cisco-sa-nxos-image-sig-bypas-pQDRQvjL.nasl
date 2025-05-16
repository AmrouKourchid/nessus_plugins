#TRUSTED 96cf0213b2ae8ec4c1c3418f27bf7f3e745c78bc9e0db724c6ceda23a33c6521fdf198ca9e97e6233f1749cb1257a99ed97985cf356f16e588b1c4d96214b2ce0374fc35cee85709037a5a03a42e6734a84837d7cf2bdefdfbeaa700f6a7858ba2ee3c3cb3009bec55be196a409470cf6f5496f882b28a9cf55a93117628d2a89eeea7fe8a1bac734e850b9e20accae5976eb27ed3819f8a6000d552be847eb09a66653b03080ae5810fe82b999e7f2f19a63c9e023317cdaae422ed7c121a383cb5ddc89bd33179c2cb0032cd5156a724e58ddbb8cd1f91cd2a740981778b0c056ad273649c11f56273e09282cdf28e351c39e1ea545f6260ac5c75594f9b025699a53634f63ca47854b7d65c16c9418b71119e891f3c210f4070854a1be852aa5e0d94e72c364c53c9144833ac99dc232a91cf172842ae8293692d2bd5c85ce2da9fdf2f670bdcb2944efa618280db0eb2cd43ee5a4f76eaae5c7292e78c92eb696752c26e012e5a8c94efdd9cea5dc65b329f2b4ed4451d5f9b11b7dd6168a79007beff7ab929ec7786a5011255e2daaebe1339946865769d237ebdad5f21232493a63243894ee96cab98711a5bbd36ea8773a26d532292b130c962855be2eaa74cebc6779c88102a8e6a42c27a11644689d2717ecb5df91b4f723385b4094af827dd16960229eca3f3861a25ad2d94463875d533a65906a0527a8db334b9
#TRUST-RSA-SHA256 71ebd0596f6abe31d2a22c75e015187a1c09e2ab6950027ad4a95f0ce92443daaefa9699f892190702f73f1110b3cf48e017749c3b1fbc75555dc0ada4a7b585df27f06928dfd13f364089b72969e09f26a92e6219bcbc684ef978406220192aba7679bbdb86bd4b228227277f72334705586fb5136f8aa038524c86c59e8656b72092b211d0d3494dba6117352c86f63d2eeeeb9a11416d843205e33c64019a0d4252fb9abe265e65ff52b3ae8d0b4ff35eab56e7b4bc4fa01e2cfd4344f2daeeee60001ff149b8d53d75a01e243499ec8703d2e67400cf83133508d19749089a4b7c3cc98603eecfe58d76703cea771d87c0e1fcea259edcf0b1a025fc2c749b1db99d1c2a25040292d488aee8b8ee9affb836c233a03bf40886489dd1e4bb7f54444be4ee1a82241f72b2503199f6295e1166897a0e02633f591b2b343b9453c4c26a4ab87ff95d3d92927cc86e8e78749f1baa97859f47f63abc83973bc74ed6eca0b397b171fcd512274275475d8f858f6627c7668f5f281a903db1267c87aeada9a5cdca69abc98083e157d6ba7d633db0dd2952458eff051f2387cf1781007f606bbab8c7f46b20ac938796e3fda05d069a00f0ebde9db7f04cddfb1cebb247a61947fc6913412cc8a0a864345fd3390349fb0a97d318f7753cd742745afa9d2e15cff9d0259dc1ce677d8e048962053140c906f1bf6f988fe7b6e60a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213166);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/06");

  script_cve_id("CVE-2024-20397");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh76163");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh76166");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj35846");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm47438");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn11901");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-image-sig-bypas-pQDRQvjL");

  script_name(english:"Cisco NX-OS Software Image Verification Bypass (cisco-sa-nxos-image-sig-bypas-pQDRQvjL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote device is affected by a vulnerability.

  - A vulnerability in the bootloader of Cisco NX-OS Software could allow an unauthenticated attacker with
    physical access to an affected device, or an authenticated, local attacker with administrative
    credentials, to bypass NX-OS image signature verification. This vulnerability is due to insecure
    bootloader settings. An attacker could exploit this vulnerability by executing a series of bootloader
    commands. A successful exploit could allow the attacker to bypass NX-OS image signature verification and
    load unverified software. (CVE-2024-20397)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-image-sig-bypas-pQDRQvjL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e325ee8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh76163");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh76166");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj35846");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm47438");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn11901");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwh76163, CSCwh76166, CSCwj35846, CSCwm47438,
CSCwn11901");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20397");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl", "cisco_enum_smu.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var device = product_info.device;
var model = product_info.model;

# filter unaffected model families
if (('MDS'   >!< device || model !~ "^(?:C)?9[0-9]{3,4}") &&
    ('Nexus' >!< device || model !~ "^(?:C)?3[0-9]{3,4}") &&
    ('Nexus' >!< device || model !~ "^(?:C)?7[0-9]{3,4}") &&
    ('Nexus' >!< device || model !~ "^(?:C)?9[0-9]{3,4}") &&
    ('UCS'   >!< device || model !~ "^6[45][0-9]{2,3}") &&
    ('MDS'   >!< device || model !~ "X97-SF4-K9"))
audit(AUDIT_HOST_NOT, 'an affected model');

# get bios version, depending on standalone NX-OS mode or ACI mode
var aci_mode, match, bios_ver;
var standalone_mode = get_kb_item("Host/Cisco/show_ver");
if (!empty_or_null(standalone_mode))
{
  match = pregmatch(string:standalone_mode, pattern:"BIOS:\s*version\s*([\d\.]+)");
  if (!empty_or_null(match)) bios_ver = match[1];
}
else
{
  aci_mode = get_kb_item("Host/aci/system/firmware/summary");
  if (!empty_or_null(aci_mode))
  {
    match = pregmatch(string:aci_mode, pattern:"bios-version\s*:\s*0?([\d\.]+)");
    if (!empty_or_null(match)) bios_ver = match[1];
  }
}

# if no bios version was found, continue only with paranoia
var extra = '';
if (empty_or_null(bios_ver))
{
  if (report_paranoia < 2) 
    audit(AUDIT_POTENTIAL_VULN);
  extra += 'The device\'s BIOS version could not be detected, therefore assessing vulnerability status solely' +
            ' based on the device\'s NX-OS version.\n';
}

# fixes per model to check for
var bios_fix, nxos_fix;
var smus = {};
if ('MDS' >< device && (model =~ "^(?:C)?9[0-9]{3,4}" || model == "X97-SF4-K9"))
{
  if (model =~ "9124V-K9" || model =~ "9148T-K9" || model =~ "9148V-K9" || model =~ "9396T-K9")
  {
    bios_fix = '1.07';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.4(2)'}];
  }
  else if (model =~ "9396V-K9")
  {
    bios_fix = '1.09';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.4(2)'}];
  }
  else if (model =~ "9220I-K9")
  {
    bios_fix = '1.13';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.4(2)'}];
  }
  else if (model =~ "9132T-K9")
  {
    bios_fix = '1.46';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.4(2)'}];
  }
  else if (model =~ "X97-SF4-K9")
  {
    bios_fix = '4.9.0';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.4(2)'}];
  }
}
else if ('Nexus' >< device && model =~ "^(?:C)?3[0-9]{3,4}")
{
  if (model =~ "31108PC-V" || model =~ "31108TC-V")
  {
    bios_fix = '4.22';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(14)'}];
    smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
  }
  else if (model =~ "31128PQ")
  {
    bios_fix = '7.70';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(14)'}];
    smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
  }
  else if (model =~ "3132C-Z" || model =~ "3264C-E" || model =~ "34200YC-SM" || model =~ "3432D-S")
  {
    bios_fix = '5.51';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(13)'}];
  }
  else if (model =~ "3232C" || model =~ "3264Q")
  {
    bios_fix = '8.40';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(14)'}];
    smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
  }
  else if (model =~ "3408-S")
  {
    bios_fix = '5.44';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(13)'}];
  }
  else if (model =~ "36180YC-R" || model =~ "3636C-R")
  {
    bios_fix = '1.24';
    nxos_fix = [
      {'min_ver':'0', 'fix_ver':'9.3(13)'},
      {'min_ver':'10.0', 'fix_ver':'10.2(7)'},
      {'min_ver':'10.3', 'fix_ver':'10.3(5)'},
      {'min_ver':'10.4', 'fix_ver':'10.4(2)'}
    ];
  }
}
else if ('Nexus' >< device && model =~ "^(?:C)?7[0-9]{3,4}")
{
  if (model =~ "SUP3E")
  {
    bios_fix = '3.10.0';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'8.4(10)'}];
  }
}
else if ('Nexus' >< device && model =~ "^(?:C)?9[0-9]{3,4}")
{
  # ACI mode
  if (!empty_or_null(aci_mode))
  {
    if (model =~ "93108TC-EX" || model =~ "93180YC-EX")
    {
      bios_fix = '7.71';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'16.0(8f)'},
        {'min_ver':'16.1', 'fix_ver':'16.1(2f)'}
      ];
    }
    else if (model =~ "93108TC-(FX$|FX3P)" || model =~ "93180YC-FX$" || model =~ "9316D-GX" ||
            model =~ "93180LC-EX" || model =~ "93216TC-FX2" || model =~ "93240YC-FX2" ||
            model =~ "9332C" || model =~ "93360YC-FX2" || model =~ "9336C-FX2$" || model =~ "9348GC-FXP" ||
            model =~ "93600CD-GX" || model =~ "9364C" || model =~ "SUP-[AB]+" || model =~ "93108TC-FX3H")
    {
      bios_fix = '5.51';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'16.0(4c)'}];
    }
    else if (model =~ "93108TC-FX3$")
    {
      bios_fix = '1.05';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'16.0(8f)'},
        {'min_ver':'16.1', 'fix_ver':'16.1(2f)'}
      ];
    }
    else if (model =~ "93120TX")
    {
      bios_fix = '7.70';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'15.3(2e)'}];
    }
    else if (model =~ "93180YC-FX3$")
    {
      bios_fix = '1.09';
      nxos_fix = [
        {'min_ver':'9.3', 'fix_ver':'9.3(13)'},
        {'min_ver':'10.2', 'fix_ver':'10.2(7)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(2)'},
        {'min_ver':'15.3', 'fix_ver':'15.3(2f)'},
        {'min_ver':'16.0', 'fix_ver':'16.0(4c)'},
        {'min_ver':'16.1', 'fix_ver':'16.1(1f)'}
      ];
    }
    else if (model =~ "9348D-GX2A$")
    {
      bios_fix = '1.09';
      nxos_fix = [
        {'min_ver':'10.2', 'fix_ver':'10.2(9)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(7)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(5)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'},
        {'min_ver':'15.3', 'fix_ver':'15.3(2f)'},
        {'min_ver':'16.0', 'fix_ver':'16.0(4c)'},
        {'min_ver':'16.1', 'fix_ver':'16.1(2f)'}
      ];
    }
    else if (model =~ "9332D-GX2B")
    {
      bios_fix = '1.13';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'16.0(8f)'},
        {'min_ver':'16.1', 'fix_ver':'16.1(2f)'}
      ];
    }
    else if (model =~ "9336C-FX2-E")
    {
      bios_fix = '1.07';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'16.0(4c)'}];
    }
    else if (model =~ "9348GC-FX3")
    {
      bios_fix = '1.06';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'16.0(5h)'}];
    }
    else if (model =~ "9364D-GX2A")
    {
      bios_fix = '1.16';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'16.0(8f)'},
        {'min_ver':'16.1', 'fix_ver':'16.1(2f)'}
      ];
    }
    else if (model =~ "SUP-[AB][^+-]?")
    {
      bios_fix = '8.40';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'16.0(8f)'}];
    }
  }
  else if (!empty_or_null(standalone_mode)) # standalone NX-OS mode
  {
    if (model =~ "92160YC-X")
    {
      bios_fix = '999.999';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'999.999'}];
      extra += 'No fixes planned. See vendor advisory.\n';
    }
    else if (model =~ "92300YC" || model =~ "93180LC-EX")
    {
      bios_fix = '5.51';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(13)'}];
    }
    else if (model =~ "9232C")
    {
      bios_fix = '7.71';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'9.3(14)'},
        {'min_ver':'10.0', 'fix_ver':'10.2(8)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(6)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
      smus['10.2(8)'] = '10.2(8) SMU (Dec 2024)';
      smus['10.3(6)'] = '10.3(6) SMU (Dec 2024)';
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "92348GC-X")
    {
      bios_fix = '5.46';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'9.3(13)'},
        {'min_ver':'10.0', 'fix_ver':'10.2(7)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(2)'}
      ];
    }
    else if (model =~ "9236C" || model =~ "9236C")
    {
      bios_fix = '7.71';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(14)'}];
      smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
    }
    else if (model =~ "93108TC-EX" || model =~ "93180YC-EX")
    {
      bios_fix = '7.71';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'9.3(14)'},
        {'min_ver':'10.0', 'fix_ver':'10.2(8)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(6)'}
      ];
      smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
      smus['10.2(8)'] = '10.2(8) SMU (Dec 2024)';
      smus['10.3(6)'] = '10.3(6) SMU (Dec 2024)';
    }
    else if (model =~ "93120TX")
    {
      bios_fix = '7.70';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'9.3(14)'}];
      smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
    }
    else if (model =~ "93108TC-FX" || model =~ "9316D-GX" || model =~ "93180YC-(FX$|FX-24)" || model =~ "93216TC-FX2" ||
            model =~ "93240YC-FX2" || model =~ "9332C" || model =~ "93360YC-FX2" || model =~ "9336C-FX2" || 
            model =~ "9348GC-FXP" || model =~ "9358GY-FXP" || model =~ "93600CD-GX" || model =~ "9364C" ||
            model =~ "SUP-[AB]+")
    {
      bios_fix = '5.51';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'9.3(13)'},
        {'min_ver':'10.0', 'fix_ver':'10.2(7)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(2)'}
      ];
    }
    else if (model =~ "93108TC-FX3$")
    {
      bios_fix = '1.05';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "93108TC-FX3H")
    {
      bios_fix = '5.51';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(2)'},
      ];
    }
    else if (model =~ "93180YC-(FX3$|FX3S)")
    {
      bios_fix = '1.09';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'9.3(13)'},
        {'min_ver':'10.0', 'fix_ver':'10.2(7)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(2)'}
      ];
    }
    else if (model =~ "93180YC-FX3H")
    {
      bios_fix = '1.09';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(2)'},
      ];
    }
    else if (model =~ "9332D-GX2B")
    {
      bios_fix = '1.13';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.2(8)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(6)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['10.2(8)'] = '10.2(8) SMU (Dec 2024)';
      smus['10.3(6)'] = '10.3(6) SMU (Dec 2024)';
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "9332D-H2R")
    {
      bios_fix = '1.07';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(1)'}
      ];
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "9336C-FX2-E")
    {
      bios_fix = '1.07';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.2(7)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(2)'}
      ];
    }
    else if (model =~ "93400LD-H1")
    {
      bios_fix = '2.10';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "9348D-GX2A")
    {
      bios_fix = '1.09';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.2(8)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(6)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['10.2(8)'] = '10.2(8) SMU (Dec 2024)';
      smus['10.3(6)'] = '10.3(6) SMU (Dec 2024)';
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "9348GC-FX3")
    {
      bios_fix = '1.06';
      nxos_fix = [{'min_ver':'0', 'fix_ver':'10.4(2)'}];
    }
    else if (model =~ "9364C-H1")
    {
      bios_fix = '1.06';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "9364D-GX2A")
    {
      bios_fix = '1.16';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.2(8)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(6)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['10.2(8)'] = '10.2(8) SMU (Dec 2024)';
      smus['10.3(6)'] = '10.3(6) SMU (Dec 2024)';
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "9408")
    {
      bios_fix = '1.11';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.3(6)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['10.3(6)'] = '10.3(6) SMU (Dec 2024)';
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "N9K-SUP-[AB]$")
    {
      bios_fix = '8.40';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'9.3(14)'},
        {'min_ver':'10.0', 'fix_ver':'10.2(8)'},
        {'min_ver':'10.3', 'fix_ver':'10.3(6)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(4)'},
        {'min_ver':'10.5', 'fix_ver':'10.5(2)'}
      ];
      smus['9.3(14)'] = '9.3(14) SMU (Dec 2024)';
      smus['10.2(8)'] = '10.2(8) SMU (Dec 2024)';
      smus['10.3(6)'] = '10.3(6) SMU (Dec 2024)';
      smus['10.4(4)'] = '10.4(4) SMU (Dec 2024)';
    }
    else if (model =~ "9800-SUP-A")
    {
      bios_fix = '1.12';
      nxos_fix = [
        {'min_ver':'0', 'fix_ver':'10.3(5)'},
        {'min_ver':'10.4', 'fix_ver':'10.4(3)'}
      ];
    }
  }
}
else if ('UCS' >< device && model =~ "^6[45][0-9]{2,3}")
{
  if (model =~ "FI-64108" || model =~ "FI-6454")
  {
    bios_fix = '5.50';
    nxos_fix = [
      {'min_ver':'0', 'fix_ver':'4.1(3n)'},
      {'min_ver':'4.2', 'fix_ver':'4.2(3n)'},
      {'min_ver':'4.3', 'fix_ver':'4.3(4a)'}
    ];
    smus['4.1(3n)'] = '4.1(3n) (Dec 2024)';
    smus['4.2(3n)'] = '4.2(3n) (Jan 2025)';
  }
  else if (model =~ "FI-6536")
  {
    bios_fix = '1.6';
    nxos_fix = [{'min_ver':'0', 'fix_ver':'4.3(4a)'}];
  }
}

if (empty_or_null(nxos_fix))
  audit(AUDIT_HOST_NOT, 'an affected model');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwh76163, CSCwh76166, CSCwj35846, CSCwm47438, CSCwn11901',
  'disable_caveat', TRUE,
  'extra'         , extra
);

# check detected bios ver against fixed bios ver
if (!empty_or_null(bios_ver) && !empty_or_null(bios_fix))
{
  if (cisco_gen_ver_compare(a:bios_ver, b:bios_fix) < 0)
  {
    reporting['extra'] += 'The device\'s BIOS version was detected as ' + bios_ver + ', which is vulnerable according to ' +
              'the relevant vendor advisory. Follow the vendor\'s instructions to upgrade BIOS to version ' + 
              bios_fix + ' or later.\n';
    cisco::security_report_cisco_v2(reporting:reporting);
    exit();
  }
}

# bios is patched or not found, perform regular NX-OS version check
cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:nxos_fix,
  smus:smus
);
