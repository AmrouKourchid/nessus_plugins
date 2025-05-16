#TRUSTED 6cf084bd8049db95ad8ee57c8f06fef1cb7e1066767cbae6420d32cef4e0f6909acc5b2d18aa099195b647d953dd9d9fd905a62ae337f2668ab4f90e27299094a9b763b23aef9db9e4b33e5f57396a633bb0416284542c173eb5af4532d69e1ea1a26a5ecabec85eccf34ee05e805f13598cbe5dc910da80358dffc469f8c90ef11742b079112cafa4a9b78693f48355e5b4672c8b214ddd063abe2c783f432900dc8538b94bcf21ebfef2dbf913fcfece00c358babff07042788d04027b6f0a216c1c8fe350dfcd85834bb46bc717cd45eb4ab85cda60846bce876feb0835e5dfe4c9d1e2a93dc79700429d53bac57eb41708e50314ca59db0057064668435d68b052e217a90cf72c2a21e08a19a9a923d3379796a9376c21cc183757a07e4dad3c8c06d5a3c461f3dca3ce6634ac2a96715eee4acac8c819d40cb3c300fdccc723977d4541230a9b77327a0c4ce61de424c01587b047c05b7f597a222e102aeec27e856ce065053f54002f21b589d357ce90d5fc08d7d40179b58b5faec1056db3ab5f91071eb6d8586e2d3821e8a1871843df132feafed942b596635ff56f4f3ca6402f48a565dd6d35c5feaf22409cd2c4d6f72d55ac498161ed8e0a727d0a39ed1188fbcbed227bafe89269aa0f40d4bdedf47a5c394df42eba502dcaddb30fa57c2d8365f02dd0261ccef6d9d8daac4f954cb1a11b1a91dbda65d67453
#TRUST-RSA-SHA256 3749a36d73a85b9cf26366b6d5fddc0dd57214ba2271ec5830540ae15a71988ca15ac767fd87ef3fca8bf10f297dc5dd6fb146ffbff3b2331fe345a0a40217c555becdcfc9424d45b661a32665b1dc7d71d707c1ff39ac02aba7badf69cf16747e070cae00500c47c3d324b125ea224c50ee1e26d41e84702645b99fc95cbc1af30b9c56ed4202173e2c891ef1624f342f0b886a8e97370acfc760d035850970554141328e4e4634b688bda9eca61d98ac8af0827fd832c82a0857d5028ceb33013955293d02f62c44053d2f45e325ebf2e203bc036dcef1b76c918217c528f87a0220edd739c72c007b6e96c3fb344a398d6151d2d80f1f3cbf620687f1164f3ce64b5b58983e1716e3d84a7dc8aa239ad8eb592d0b7858590a15b707c834e9e83bd8d89241d1b6a6cc9114270a6c94b0ea72fc0e7e60a82a870ab33c421c36a1d3fdfac9cbb0579e4d076e7ce3d8792bd5bcf1a542c4b3e8a7e89fefa95b491851589776bf3a9d4c25e0a8e639c7400b48e51943303c6eac2729d90b4e3b268968d4251d68789f8b19de0f315b219740ae57395300cf0c029013899f5b121704e81b910c96c879405eccaf800025ca572fff04cdd9e07e7b97f2b5d5f8dbef8d5d13910f90b77a3fbb40c859a0ae8bc22923b125d5c6388e2b2225319eb800150de70fff23a5e46cd52ddcf4afbc54d5b0ff1a5854cb05c2241f1aca355b16
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(109210);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2018-0016");
  script_bugtraq_id(103747);
  script_xref(name:"JSA", value:"JSA10844");

  script_name(english:"Juniper Junos Connectionless Network Protocol (CLNP) Packet Handling Unspecified Remote Code Execution / DoS (JSA10844)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by an unspecified flaw that is triggered when
handling Connectionless Network Protocol (CLNP) packets. This allows a
remote attacker to crash a device or execute arbitrary code.

Note: This issue is only affected if 'clns-routing' or 'ESIS' is
explicitly configured.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10844");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10844.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0016");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

fixes = make_array();
fixes['15.1']    = '15.1F5-S3';
fixes['15.1']    = '15.1F6-S8';
fixes['15.1']    = '15.1F7';
fixes['15.1']    = '15.1R5';
fixes['15.1X49'] = '15.1X49-D60';
fixes['15.1X53'] = '15.1X53-D66';
fixes['15.1X53'] = '15.1X53-D233';
fixes['15.1X53'] = '15.1X53-D471';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for CLNS routing and ESIS
override = TRUE;

buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set routing-instances \S+ protocols esis",
    "^set routing-instances \S+ protocols isis clns-routing"
  );
  foreach pattern (patterns)
    if (junos_check_config(buf:buf, pattern:pattern)) override = FALSE;

  if (override) audit(AUDIT_HOST_NOT,
    'affected because neither CLNS routing or ESIS are enabled');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
