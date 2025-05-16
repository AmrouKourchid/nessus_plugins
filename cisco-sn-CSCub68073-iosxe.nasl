#TRUSTED 1ed5e837f91ddc7c39d725a71beeed43259c892a16c78ffa17e62e23e16c1267121e80ee3b26870e1c8a3f41fe0616c7fc281282d67edf200d74876122e24acc17c6c8d14e0705c85a3eaa7b5577b2c7241d025b4771e11c173a8ff830768ea4c156beb6bbe68ba01fc3bc0e20fd790a3623e87827aa257ac8a382c2e69dd97a53f764575355c66756580cd7bf027d0eb37141d506839696ddb0f8331874f1fa8c37a6ebf9d82df85343cf7eb4360c5c1522c06b3433b76eb6a13121091d94c5d56a93bb333db8e15b87166b269a703941f4a86b3a5d370210d2abaec9e2e5e6be9a611922536c43c9b7aadb2f02d1c69d4d0281fee2e56e4e25c222046a4b76cd920c3e5b45bd1c0e8b6f7bf015602746c70caf3b78ce02c30d238040ef48f13493aff1a70d3492dcaf6f92a6e5c5a74aba0a29340bc57ef88721e7fdcdde3597ed8f69b9c8664c32233c6e7d7cb49e6fe87aa9905faeb929fa14d5b3fcbb1acb3fb3c1421de44e3001b5e8f1f668144ae03da82a9b9a5a8fe1a21b7497a07f76c986ff6be23f2b37da3b85f19f369eb062e96c365a60b4dc69ad49417ff12d4956fc596069ef7e4af6a72c99d22f0c970ad35af0ed856d1f229a573f237698e5fce8bba9d2d4469ca16b1c21670fa96e7d061695504bec76d43a5c6efdc03a70a2c923a9d1bdeb9fc9c52d5a8e701eee73c050e8f4bf06b043234e0ecfd069
#TRUST-RSA-SHA256 32b9014f83dee7baa19d0d7ae03714bb6f7d8734b63223b5306645b07041ea2a36437956b55544a14e76554bad31414efcb668c14f923c40d8146432f98563e3f646f61be263169de86d63091e0fea866456ef567bed3bce51356e41939216e574cb2bcaebfc2b6396956b81b59e849a529fe62ed09f0343d497d88dca0606aebc7abfa2a86e38a5ee2fcb5849a0142288b93298984d06fd4e041317f956c9ee608ec7f2148f7c22377d5ef2ca2156339a39a9f906ca5d4a32c68075f5c96c12dd01a5df8bfd16b1a7619bc4f131becdfb7e4979d0454216394ee5f8fb265b36982bc5442bef22eb8610e178a81b987645b7a58a12d18d571da6a9e3bb42715fc5702994fcf5d93aa8747e0975cb0e77e11929dd16dd21fcd8c4e8ac78f51452c74aef8a0113bf5e1fdef20c0f0a72e02128d0bad934a36aed1a9668ec6579adc67657fe14f06120ad2b92aaabaf2d01c3289c9658437687a2f423fa680f2b74a5567888e4621e475a5e0728b2f448cc99ed106b8e5c31cc9b8cb127d6896ddf69e3ed6e341ffe84cce325288ead5f10f4559cb24f097455fc2d81561e9021d5fd11c4ac9abd928b3ba32879d1ed6bd0d0a31422a11a70c4a4a98789c0da1c8928380bb94a0b7fcd18e01c60e351b2abbab465d4a2db527e5e7a3ca1788c1adf3e506b544858874f1ac0c5e39a386d8aebfad032d78e6b6c13a66465e4531dda
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82587);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2015-0641");
  script_bugtraq_id(73337);
  script_xref(name:"CISCO-BUG-ID", value:"CSCub68073");

  script_name(english:"Cisco IOS XE IPv6 DoS");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco IOS XE software running on the remote device is affected by
a denial of service vulnerability due to improper parsing of IPv6
packets. An unauthenticated, remote attacker, using crafted IPv6
packets, can exploit this to cause a device reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-iosxe#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4cbb5bb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCub68073");
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

# CVRF
if (version == "3.1.0S") flag++;
if (version == "3.1.1S") flag++;
if (version == "3.1.2S") flag++;
if (version == "3.1.3S") flag++;
if (version == "3.1.4S") flag++;
if (version == "3.1.5S") flag++;
if (version == "3.1.6S") flag++;
if (version == "3.2.0S") flag++;
if (version == "3.2.1S") flag++;
if (version == "3.2.2S") flag++;
if (version == "3.2.3S") flag++;
if (version == "3.3.0S") flag++;
if (version == "3.3.1S") flag++;
if (version == "3.3.2S") flag++;
if (version == "3.4.0S") flag++;
if (version == "3.4.1S") flag++;
if (version == "3.4.2S") flag++;
if (version == "3.4.3S") flag++;
if (version == "3.4.4S") flag++;
if (version == "3.4.5S") flag++;
if (version == "3.4.6S") flag++;
if (version == "3.5.0S") flag++;
if (version == "3.5.1S") flag++;
if (version == "3.5.2S") flag++;
if (version == "3.6.0S") flag++;
if (version == "3.6.1S") flag++;
if (version == "3.6.2S") flag++;
if (version == "3.7.0S") flag++;
if (version == "3.7.1S") flag++;
if (version == "3.7.2S") flag++;
if (version == "3.7.3S") flag++;
if (version == "3.7.4S") flag++;
if (version == "3.7.5S") flag++;
if (version == "3.7.6S") flag++;
if (version == "3.7.7S") flag++;
if (version == "3.8.0S") flag++;
if (version == "3.8.1S") flag++;
if (version == "3.8.2S") flag++;

# From SA (and not covered by Bug or CVRF)
if (version =~ "^2\.") flag++;

# Check NAT config
if (flag > 0)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (
      (preg(multiline:TRUE, pattern:"^ipv6 address ", string:buf)) &&
      (preg(multiline:TRUE, pattern:"^ipv6 enable ", string:buf))
    ) flag = 1;
  } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCub68073' +
    '\n  Installed release : ' + version;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
