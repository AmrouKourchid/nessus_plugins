#TRUSTED 126f7a4704614c1ae649bd6e1fcb124ba36a24e536abe74b24355aced188fd33aee2ce7f9c222923fcc7baafa9c850a4757ea945d3b7f146fd65cc4f4a32f00a06b0640ded0c4e3c4fbec078783d3dd3f7beb45734082db59efae326b4120779e9fc7d6f90b888068b715be3ba95dd02dcc56c2a1802c9a001aaa8a9710d5f273a4c53c92b10124d17db113ef3fbb61366305ec6b85bbbfde924114badad3e352542d3a05ea4d9aa09e9c65c3fcf3c766722aad6e5017285b71079f4f8fc31b225c58e616117bc4ebaf6945b430a0de56bddf44f100b2d15225b6fa73b44e0468913cc2e2103dca3605056d7dc285d90864e6b8cdd2ffc347e15f82d9f36ff9cb636dfadc8a4cbee3c7df481d993d982b49b529ecab7e38ee7f3b9379a9f053559d9bed2271bd5ad7e395a6d1804e249aef74be1fe5ba58270be41f3e194e607781929afeda71b9b2780187cc31685bb15a325759e12ef1ade608b2a991d499ce5441cd3dbfb9b67c8624f0b236328c5429689f0c156062604042e011b069ef451875218a5d5ea49c3751eca50a8ad3272c6b29ba6ecff1476240ba28a855b6195268f101a0f7b2dd23e961838fa682c2d1162e9e67ab4877ddd3a2695500bc2c6bd59efbb8cd14b93e39af9eb619bdbd5cd40dab848e50ba10daebaa4824c457e8a87d25ec6eb60b118b31e81cc511d9010de44802552e6b93f38c2dcbc5546
#TRUST-RSA-SHA256 496282ffb08947aae28c719784a7f3e0aa73620ca2f757d4ac33d1ec2231c3a5d5dd282d0ed16a44dffb9c2b9ca6aed60f576702502200129309a6450bfc0f1a9b8e79ccf8cfa7ec695f3cbb499ff56e15e54799c734c951529377b643aef404342908c8b1b6e0e0084e0ff0773e7d6c2706f2b4841a7b5f4a790d571f3323ac19a6f8af8c3570e37931f7e62d4cfca006655206cf4077ab53907087644abeee4416c819d413c789ae40191474b25a0e49995f67e986a274e95d32f1c33121c775e69fb1fb034be09a0bb21c66510cab38907a620f37ed39d7e530c627bcd4618f30ec3beab33bce5430abff908c8fbe706c850439e39b21262f04ee50ce9bbc45babacdfbbd5f17c18eef67f1b7e0f9e5f885508a73e099c45107002802089ca0828d25778a69d7958270febd3121dfdf372aa42a338ca20f4f467dff85b6182b5eaaabbc961c77eaf4c2e324a813981d3dde790a0fe00c9d0dbbd5b7e868aefb5a18ce3659b9e6d8492ad761f1d77fd7451834cd9906df85814951c06e73bc1adf62a0c6b14b1a907029ee968217ee60da008ebaefd92adb24188a6a166c5e094401d707e701f749e219e5ba5dd72777dcaa2ae9885d5a62ea2195fd506090e01fb18017b809ea6bef64fb401525ceda3987ce1d455ff7a43f9d4a61a0cc67a6adfa6151a95112db9957e51dd3c36e707690f0ce2e4cd884d820da23343086
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10547);
 script_version("1.27");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/22");
 script_cve_id("CVE-1999-0499");
 
 script_name(english:"Microsoft Windows LAN Manager SNMP LanMan Services Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The list of LanMan services running on the remote host can be obtained
via SNMP." );
 script_set_attribute(attribute:"description", value:
"It is possible to obtain the list of LanMan services on the remote
host by sending SNMP requests with the OID 1.3.6.1.4.1.77.1.2.3.1.1

An attacker may use this information to gain more knowledge about
the target host." );
 script_set_attribute(attribute:"solution", value:
"Disable the SNMP service on the remote host if you do not use it,
or filter incoming UDP packets going to this port." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0499");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/11/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/06/07");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Enumerates services via SNMP");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2024 Tenable Network Security, Inc.");
 script_family(english:"SNMP");
 script_dependencies("snmp_settings.nasl", "find_service2.nasl");
 script_require_keys("SNMP/community");
 exit(0);
}

include ("snmp_func.inc");

var community = get_kb_item("SNMP/community");
if(!community)exit(0);

var port = get_kb_item("SNMP/port");
if(!port)port = 161;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

var soc = open_sock_udp(port);
if (!soc)
  exit (0);

var svc = scan_snmp_string (socket:soc, community:community, oid:"1.3.6.1.4.1.77.1.2.3.1.1");

if(strlen(svc))
{
 security_hole(port:port, extra: svc, protocol:"udp");
}
