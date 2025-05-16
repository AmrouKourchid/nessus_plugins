#TRUSTED 0780b80f69ee8278f503dd241b0c0bf1b3fc7906498fba4f4ff054f1ad24bca3cf197b85f1d7be21fcb62b16d47cdb1a852a781d69db51153c765a57c6ff57b97a71bfe730281012c5094d1f9a4067625c5c3593819513701cbe591f9bc558cbdf5a88a6087e7d472620ef0701f47368ac9f0c7c714066ed3a20ea6e0e9e3b16e7c33c335f8f9bf5f3b37c096e7e87015aa50a3af8a169f6785f9bf8e42314afed6282ffdd38d2f7adb6b8c5e5428aadc8751128a979bdfc8b358fcf570222c4622593da850073a007ad81ce9379e114c4161556996735b224c221ece812c3f7a5dd3fd0027c72be6ea091a66da2f259e32a446e2a77c8004d6f870ba6734ccb402cc7469e07540b70eb85a267263331e7fa797f659257d656e0fa51069b66f1d8ae4b8ad435e4f1277cb63b0c3b8ee9e49efe6cdc30067491277a931efd4c18a7f6651287a99cb76cf79d8b707fded4d50c609a6e6afb0f9e53d292869d8e031679ca495aabfdb76b6406018878e3f9033ac6293c5cdde492be8466047a0d5299656b9d5d29387ef5464691395b145b2959b09c5b2ff22d703ef82a33f4df560e8b8286c2840e378caf98b13b549ff0eea60bfa854309fa746e758dba259811f7bf099d6f3a4f7dfbccc7433b939b602572016deca80b2e7caa971168390aa9e9b2e34716b21f124ab994aedb3b93706cbaeef30a698e6726c3c178410d63e2
#TRUST-RSA-SHA256 697511a6a73752b33a94b412a6b06517b0df22c9c7609ea9e3daabc5df73daf0743764c8709095b8ee312f592017272f8a29bf2d1acf787ee638c75cef7de60ba2ff2189f26760bb65ee5499f1d6750715d1cb5f0eff975f572dec7c8deb83e424c560406a862af0651992c1eb339a49271c7889a2108e6133ed3f594ba78525b29cb869702b7bb63280e44e7708650348486fa1831515c4830c4ab9a060e4253335d798a10650d290c7e8d8d6ea30a5c3ca5ed70acab074d361d6cd5a6ec0ac9f66e6a69824efcaaaccaff4c72c72fbc57cf1999908c6332708de4661f5deb00064c5358a034765302fb42d59a5cccada714977dfaa8deefeba9a79a2f4a498047296ef6cd7d99968f3195914b65d3e6e145fb82ea0305d9879314e1f4ff530fe13d5834a7ac4361dca7c7430a003b1fd8ca25cf2a0188c0054c8a6a6e7187d9a9ab462422553a7aca238f2cc9621fc3cad62926b06784fdd035fcf06fb5c3b6b1c4a8ad9beff556250e7c9234bff1627f80909200e853156145cfb47c5f279fa0bd6ecc03d0d38213bdbf3ae16ad77a01b4766009b6d6e69896157a0f7dd33fbf8e9109769645bfa79160ffbd9162deea6427527472d8d89f0bf94fa7dc990f8b209f9bd1540b246d93fde9a06bc01eee7c740a58efdba0b1b7d91b6e12bac030195fd9f68d3476116bc331ab58321bc636b32a404eee9ecde016926c6f9d6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93480);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2015-7547");
  script_bugtraq_id(83265);
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160218-glibc");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy36553");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy38921");
  script_xref(name:"EDB-ID", value:"39454");
  script_xref(name:"EDB-ID", value:"40339");
  script_xref(name:"CERT", value:"457759");

  script_name(english:"Cisco Nexus 3000 / 9000 Series GNU C Library (glibc) getaddrinfo() RCE (cisco-sa-20160218-glibc)");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco NX-OS software running on the remote device is
affected by a remote code execution vulnerability in the bundled
version of the GNU C Library (glibc) due to a stack-based buffer
overflow condition in the DNS resolver. An unauthenticated, remote
attacker can exploit this, via a crafted DNS response that triggers a
call to the getaddrinfo() function, to cause a denial of service
condition or the execution of arbitrary code.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160218-glibc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae76a668");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy36553");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy38921");
  # https://security.googleblog.com/2016/02/cve-2015-7547-glibc-getaddrinfo-stack.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?94dd3376");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version or install the relevant 
SMU patches referenced in Cisco bug ID CSCuy36553 / CSCuy38921.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7547");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# only affects nexus 9000 series systems
# and the 3000 series systems listed in the advisory/bugs
if (
  device != 'Nexus' || 
  model !~ '^(3016|3048|3064|3132|3164|3172|3232|3264|31128|[9][0-9][0-9][0-9][0-9]?)([^0-9]|$)'
  ) audit(AUDIT_HOST_NOT, "affected");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

override = 0;
check_patch = 0;
vuln = 0;

if ((
  # Only CSCuy36553
  version =~ "^6\.1" ||
  version =~ "^7\.0\(3\)I1"
  ) && model =~ '^(3164|3232|3264|31128|9[0-9][0-9][0-9][0-9]?)([^0-9]|$)'
) vuln ++;
# CSCuy36553 & CSCuy38921
else if (
  version =~ "^7\.0\(3\)I2\(1[a-z]?\)" ||
  version == "7.0(3)I2(2)" ||
  version == "7.0(3)I3(1)"
) vuln ++;
else if ( version == "7.0(3)I2(2a)" || version == "7.0(3)I2(2b)" ) 
{
  # flag vuln in case we can't check for the patch.
  vuln ++;
  check_patch ++;
}
else audit(AUDIT_HOST_NOT, "affected");

# check for the patch on 7.0(3)I2(2[ab])
# audit if patched, assume vuln otherwise
if (check_patch && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");
  if (check_cisco_result(buf))
  {
    # Modular products 2a - 2 patches
    # nxos.CSCuy36553_modular_sup-1.0.0-7.0.3.I2.2a.lib32_n9000
    # nxos.CSCuy36553_modular_lc-1.0.0-7.0.3.I2.2a.lib32_n9000
    if ( version == "7.0(3)I2(2a)" && model =~ "^(9504|9508|9516)")
    {
      if 
      ( 
        "CSCuy36553_modular_sup" >< buf && 
        "CSCuy36553_modular_lc" >< buf
      ) 
      audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patches are installed");
    }
    # ToR products 2a - 1 patch
    # nxos.CSCuy36553_TOR-1.0.0-7.0.3.I2.2a.lib32_n9000
    else if (version == "7.0(3)I2(2a)")
    {
      if ("CSCuy36553_TOR" >< buf) audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patch is installed");
    }
    # All products 2b - 2 patches
    # nxos.CSCpatch01-1.0.0-7.0.3.I2.2b.lib32_n9000
    # nxos.CSCuy36553-1.0.0-7.0.3.I2.2b.lib32_n9000
    else if ( version == "7.0(3)I2(2b)")
    {
      if 
      ( 
        "CSCpatch01" >< buf && 
        "CSCuy36553" >< buf
      ) 
      audit(AUDIT_HOST_NOT, "affected because CSCuy36553 patches are installed");
    }
    
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fix               : see solution.' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
