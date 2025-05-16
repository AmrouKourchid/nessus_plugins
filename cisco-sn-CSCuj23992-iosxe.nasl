#TRUSTED 8f47da26a7a2a57e4ab0b01d7efcd598d6fc7ac8dd5f81b86aae4135f6a6396ee7df6111f8d36b2069e06636364eb71b2e9e3d0ecfca327d71ccfaf84e2b9c11c8c9798e9b63324f35c78d1829bba200ff39ff2583bb7bb6725b88b72bf215c3110a601f286d1351ead476fedcfb1d701443af7355ec08ce6cf6bce7853d03e6c45d8970e47f4768a5fb5f3cc129033619cb4523c5b5500d6274e25d06adcd054efe9ff158682901c22fb892782716d9eff18f9ce2b365638a57f612a54e702ffab35c54869791320343249ec351d6ee9343d8348b960a2f6f6fda78ec43e1d47144ec8b7963c36e97c5a1225bf3456370c121074fc0336012cbd7ff8abce8c8350be157ae71f42138d09d162e99b2420966576439bfa9306bfaba2bb78f441c00a12de1e43957478f35b525348306bfb4ef18cb775f7508c38d3d257898687212964d59c8b63e7f3a56407ab8a887f458c4f96efc0b8206d708c052b59d1fd5b1b1635fa21a2c89e13265638d34cb9c6a5b9ea465c8122c530a62d3f8ecc397fc16867030c8b6309b4cfb01a16dc87a1e1c826bcaf70ea2400449ffa8875ddf738b57ca84dfc143b302e32801c6ec459b017f342c132b367f17879e120bb7ed52fbfab20f3bc9ddc75d589b55c5a2c02ef16457d4f0456788b8dd054359ccf6100fe3380d266b521b0c30929f53905b34487c165dd638de80c626c5115ed640
#TRUST-RSA-SHA256 95e798dbfe1365c5c673c194135def61a157af6ed9cc88a238668278e249a8a13a2e002f8996b740a815cc9e63db016d59218d0b04d618cb77ac2dc4895b1d2d9129e0d8fdbf6dbde1222503ad1079ad079cf26b01061ca59ecfead736bfb11a2003a33184e76c57205257324575ab73606d2150ef0de7fadfc59418c8c2ca85f0f83d291d9ec6ded04cb0d961a1cd2ecbfc1cd90ba2332850f82b189c20307c585edb42e17f42864b98c34e650637ec664c19b7d89f8232e32b5918017c5769da9a7ba0608a7c3f29e8e8b7f1c4794b35419fe420b638e571228fc86a0703df9823b768154367bead9a804d1af3910cc5bf0f10d4c296a2f27613977cb871a90092d2c1112154c7e72dc810dd0598d8e30206e9deaa8dadca083fa44ecae9b53158c7656ea0379fdef2ac32daf805ca3bfd301f1f25012fc0255e4a9defb5ff7cf1ee1b24d5f1de9e011d36807db580da6d57bb5d21c25cef7449e566d79bf82ebf5b8579e92d5592b7ff356318a959b18e73518f6b7aa4b4c76a8e39a20699e5dce91feb5fcd38611b48ee9beb2f38a7fa07c01e26292b6100ada9b2fd9943def0a066e1bc401763db3fd9414e01f6c61385dd26c49eec96fe81cd095f1f50cf80765f4ea2db2077455ae45b97d916e7ff41ad83edb592deda45ff0639f77a63a21ea70113968889b3c9cb7ef0cc77cde49834284e9524e99bd933341af15b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78691);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2013-6706");
  script_bugtraq_id(63979);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23992");

  script_name(english:"Cisco IOS XE IP Header Sanity Check DoS (CSCuj23992)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote IOS XE device is
affected by a denial of service vulnerability in the Cisco Express
Forwarding processing module.

The issue is due to improper processing of MPLS packets. When certain
additional features are configured, an attacker can exploit this
vulnerability by sending MPLS packets to traverse and exit an affected
device as IP packets. This may cause the device to reload.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=31950");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=31950
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4249565d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuj23992.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6706");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# this advisory only addresses CISCO ASR 1000 series
model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");
if (model !~ '^ASR 10[0-9][0-9]($|[^0-9])') audit(AUDIT_HOST_NOT, 'ASR 1000 Series');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
override = 0;

if (version == '3.9.0S') flag++;
else if (version == '3.9.1S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag > 0)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (
        preg(multiline:TRUE, pattern:"ip cef accounting", string:buf) && 
        preg(multiline:TRUE, pattern:"tcp adjust-mss", string:buf)
      ) flag = 1;
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag > 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCuj23992' +
      '\n  Installed release : ' + version +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
