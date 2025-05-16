#TRUSTED 869d2188585b57ec84ca47bc5b532fa031caf2558208de0d202cc5692a6c492f82b1716624e9c3f6d99bb18fbd53c1304070d43787b5fa02483885bee59c2c32c67a25575a58575a4a7569b58bab74db7a79f6758939376d379cf128acd0a3513a201488f7c8cdcb81025d852120109f2e37d65e00ffd265a73684e770782ea90e1c4859a6e93140b25929674c8a79a608aa5ca27c8b3b0982a02318f83381384a5482d363b7a085e42fd588a79a59da2c2041be285fbba47465a64b570c97d9e068e40cd0e55d130aee22093f635fe3f27cea19b8ceeb511999e0a28e2f53e75d2a0f4f511ee88e03b427165d2e3899978e14846621b3a84657619ead06dfcbd53fa3236e79ebee47a426c63b718eeae3a08ca63090377e304fa16343861ba965d31b96e5817120a0bcc06fec0a4cad00f741390ada8f07cc2e5936576f6c9469178bbf0f870f4c42e69a30648a9abf0da02b70979a119bd223f8ceb3abbcff8004e3fcc4d66a2768cce07f7a9e26daf5bd33725f293d50a6d8c91f100ae5e5debd97f3d6f7854d289055afa8c3e5ab5cedf8f1bf1969f821b683c551efa8683592e732ed2e0588176b343beef46d07fa60cf571cf57755998e4591a7917411935d3d79ab93810adce4aed8e41554e7ee5faec04c03f9d1a73fc344512ca00d534097327d53b36f7a33acc61137e3997168174201fc6d7a4565cf841eb1544a
#TRUST-RSA-SHA256 93b27ba97c87dceb4c0ddf8f766367a8461e3a1b61c671eb2423d51bfb2f730b7a08576106ca28344122d9d3e5d88d08f415d052f6c53b362ec87fb7d339044264292a72d363c7e92d5a2f6556caab55f415771379bccfe7ecec9c4b127f8d6c68e80c6cd50eeed37f3a904237ea77627d2c1cf211e9a41ad0fba093a2f5a34c3b40e72697d56d2c8ed797fe780458bfa03bfde27bc1597edc862fe6073717ab76ddefb31d193862806b854f2b471303c0cc7948e462fa6602d00cd896c5f8c7a96a91d68f6fb521f3f73253384d9585af3910844cd712ebe7c481e9493259f3f78d1ab478f44e2dbf725d025dd05861a490861afccfcb17d3dcda6f5a4021390640c607e9b3412f4e95e329a41cdb2fe88b0d91cb7e99bcbf69d1afbfd078385c9ebde43a969c137c07ace01b91cebf287eeb430212f50818f3498d3c226978ab06bfebbe3591d8fcd1f718cc9a082f1cc66a24b265601a611d4fc729e7a6a23c8ea5ff4ab30fcd1b8b855e991ea7f6a00645a801a6e2410341251e7ad3e65739f824436fcfb93eedf60fdd3895e8a6f8b3a940d3de7636b4e936694be1a3f91a74da9191ba2cdc6c68b49191427da0eb7b0a7c256c7cb61a8f88735b908b472ca57d3e37d4965c989e33419e048255423226e393a936e12346319bf8f44dbbfb765de9b37d52e7792183baaa1840778c26b8382db98abfc81dffb0c1fac08c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82588);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0640");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuo25741");

  script_name(english:"Cisco IOS XE Fragmented Packet DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability in the high-speed logging (HSL)
feature due to improper processing of fragmented IP packets. An
unauthenticated, remote attacker, by sending a large number of
oversized packets, can exploit this to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuo25741");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

# Per Bug CSCuo25741
if (
  !(
    "ASR1k"    >< model ||
    "ISR4400"  >< model ||
    "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

# Bug (converted) and CVRF
if (version == "3.10.0S") flag++;
if (version == "3.11.0S") flag++;

# CVRF
if (version == "3.10.0Sa") flag++;
if (version == "3.10.1S")  flag++;
if (version == "3.10.2S")  flag++;
if (version == "3.10.3S")  flag++;
if (version == "3.11.1S")  flag++;
if (version == "3.11.2S")  flag++;
if (version == "3.12.0S")  flag++;
if (version == "3.12.1S")  flag++;
if (version == "3.1.0S")   flag++;
if (version == "3.1.1S")   flag++;
if (version == "3.1.2S")   flag++;
if (version == "3.1.3S")   flag++;
if (version == "3.1.4S")   flag++;
if (version == "3.1.5S")   flag++;
if (version == "3.1.6S")   flag++;
if (version == "3.2.0S")   flag++;
if (version == "3.2.1S")   flag++;
if (version == "3.2.2S")   flag++;
if (version == "3.2.3S")   flag++;
if (version == "3.3.0S")   flag++;
if (version == "3.3.1S")   flag++;
if (version == "3.3.2S")   flag++;
if (version == "3.5.0S")   flag++;
if (version == "3.5.1S")   flag++;
if (version == "3.5.2S")   flag++;
if (version == "3.6.0S")   flag++;
if (version == "3.6.1S")   flag++;
if (version == "3.6.2S")   flag++;
if (version == "3.7.0S")   flag++;
if (version == "3.7.1S")   flag++;
if (version == "3.7.2S")   flag++;
if (version == "3.7.3S")   flag++;
if (version == "3.7.4S")   flag++;
if (version == "3.7.5S")   flag++;
if (version == "3.7.6S")   flag++;
if (version == "3.7.7S")   flag++;
if (version == "3.8.0S")   flag++;
if (version == "3.8.1S")   flag++;
if (version == "3.8.2S")   flag++;
if (version == "3.9.0S")   flag++;
if (version == "3.9.1S")   flag++;
if (version == "3.9.2S")   flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;
if (version =~ "^3\.4($|[^0-9])") flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^ip nat inside$", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ip nat outside$", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ip nat (inside|outside) source ", string:buf)) &&
      !(preg(multiline:TRUE, pattern:"^no ip nat ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCuo25741' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
