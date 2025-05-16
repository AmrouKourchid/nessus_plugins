#TRUSTED b13e537b66f6ff5bc9af0d129a4ad01c16d59710e274384ca6d3c5c2e93aaf7e1cf9e1cc687d03c0d994364498567872a6445f3c7970cdc8d1f6da688abded5ee136dfe71a9a5e675f515b58cf2c50e3a929c4c5fc7ad15ba3c0e62177332707edbe0880ae8c3a3aba8360140d28b95c3a5cfeb55ace86b5991679913e0c53b72c2c2d4e54ccb1a16984ba3ec27831d5eb9dc2d6ce701b14a045f166789c9486ebd79c0e0bf7c5d33b640233d8f818008a5395f45e87c9743fa198d9ba32bba33813a5150b1db377e36c2de4181d628b267e36ac0673068b54c4d6caa7ff3678f88404fe04c30888da7925949c9fd3928d59735c86f6e117fafa8e7e3f9523a3b8cf55d5a357be8d237e9b20f57a4ff025a30cb8b54f7d9b2bd4c64f2cd3bb45359520923a11cccc1ddc0987a763a2774b5cf7ee21fccaa489cf74aa605a3b22c057ba6b5a7bf83017d5c61803035610e6903c65357a34727dffb3590b6f2a65eb93190ddb26d3ed12a27251cbaf7a9752add64e9392b55b6372a57ce8c52baa1dec37edbc7d7337e3047d1b2b4383875530b8329002b1b47034c4a5a6b6de80110d9894798b1cd5107db87da8fb1b52c8630213446e5758442791bb1c4e72c78c2008348403b5e80ec2c44dc4c34b7b71125ecf62fd864ab2a78578504759e00670b50862cf05ccc7af5c35f109e0622fceb3e3acd94946befd62d91b81056a
#TRUST-RSA-SHA256 87fd208c8ecaf303b790835675abc01c578fcef3cf78e3a10e05b3d99a7375b1ea8e932e091f191f02194f5d62a33886f93a3bd29200a50e14def3781c05b05fb4fe5e8fc55e5b442af2b8936edb0a304c06bae9482cc36e0107eee051c111c7d062ff29a9b8ce3ce0c35ec674b3a3e2ad6ec0e714f0365539af2b06780fa1a701df0a050133a9e090a2f9bc055095318a79416f8fe4d7686f7a0f174b52e126f1715af32e17ca0132bd0ae1e29ef05a8081617e9771a19c0d45050b59bec55a7d53174de0761179564d44b1a68449141c442601acf41a05c63faa1221270c2b0ba6d2d94d7af3a9210257219ac715e0df60e7762ba107e9b2f6ac874888fff2c38dcfab93006ec6db53a72c262c68d8444935f6e9688175a2986fd30173c9f988c1f9503831aff40a1e5fab120d0480457e02afb2062cca0c2d3a608ddf354889c1afb59a07ebae17d4b3b317913ebbf8b280e89898093ad81cd5efe50d6a635bfee33441f520c3ad722a217d9b41ed96ba98129a036ba4e7af2afaddb56f107c8099e5beee74627a3efbb231e48b1617bde2f5ccb6a8e2f111ddfbd613ebcbb64f1f3a7fdac254a2ce8a8c9e154632a1cc60d2f83ebb9552be13f93d8befd1fa10df8f77d8d69c35c62e1e5126863d97e22af905c8df051d74ff45f42c104535ab97e21d77d1222d84932087629e68a13ab35d1f0efc0230edbbaaf545adbe
##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
  script_id(50543);
  script_version("1.91");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/03");

  script_name(english:"OS Identification : SSL Certificates");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on an SSL
certificate.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to identify the operating system by examining a
hard-coded SSL certificate issued by the device manufacturer.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2010-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssl_supported_versions.nasl");
  script_require_keys("SSL/Supported");

  exit(0);
}

include("x509_func.inc");

get_kb_item_or_exit("SSL/Supported");

var ports = get_ssl_ports();
if (empty_or_null(ports)) exit(1, "The host does not appear to have any SSL-based services.");

var i = 0;
var name             = make_array();
var dev_type         = make_array();
var confidence       = make_array();
var varissuer_cn_pat = make_array();
var issuer_org_pat   = make_array();
var issuer_ou_pat    = make_array();
var subject_cn_pat   = make_array();
var subject_org_pat  = make_array();
var subject_ou_pat   = make_array();

name[i]            = "Aerohive HiveOS";
issuer_cn_pat[i]   = "^HiveAP$";
issuer_org_pat[i]  = "^Aerohive$";
issuer_ou_pat[i]   = "^Default$";
subject_cn_pat[i]   = "^HiveAP$";
subject_org_pat[i] = "^Aerohive$";
subject_ou_pat[i]  = "^Default$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Aruba Clearpass Policy Manager";
issuer_cn_pat[i]   = "^clearpass";
issuer_org_pat[i]  = "^PolicyManager";
subject_cn_pat[i]   = "^clearpass";
subject_org_pat[i] = "^PolicyManager";
dev_type[i]        = "embedded";
i++;

name[i]            = "Avocent MergePoint Unity KVM switch";
issuer_cn_pat[i]   = "^Avocent MergePoint Unity$";
issuer_org_pat[i]  = "^(avocent|Avocent MergePoint Unity)$";
subject_cn_pat[i]  = "^Avocent MergePoint Unity$";
subject_org_pat[i] = "^(avocent|Avocent MergePoint Unity)$";
dev_type[i]        = "switch";
i++;

name[i]            = "Barracuda SSL VPN";
issuer_cn_pat[i]   = "^sslvpn\.barracuda\.com";
issuer_org_pat[i]  = "^Untrusted Certificate";
issuer_ou_pat[i]   = "^Untrusted Certificate";
subject_cn_pat[i]  = "^sslvpn\.barracuda\.com";
subject_org_pat[i] = "^Untrusted Certificate";
subject_ou_pat[i]  = "^Untrusted Certificate";
dev_type[i]        = "VPN";
i++;

name[i]            = "Blue Coat Appliance";
issuer_org_pat[i]  = "^Blue Coat SG[0-9]+ Series$";
subject_org_pat[i] = "^Blue Coat SG[0-9]+ Series$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Canon imageRUNNER Printer";
issuer_cn_pat[i]   = "^Canon (iR-ADV|iR Series)";
subject_cn_pat[i]  = "^Canon (iR-ADV|iR Series)";
dev_type[i]        = "printer";
i++;

name[i]            = 'CISCO IOS\nCisco IOS XE';
confidence[i]      = 75;
issuer_cn_pat[i]   = "^IOS-Self-Signed-Certificate-[0-9a-fA-F]+";
subject_cn_pat[i]  = "^IOS-Self-Signed-Certificate-[0-9a-fA-F]+";
dev_type[i]        = "router";
i++;

name[i]            = 'Cisco Intrusion Management System';
issuer_org_pat[i]  = "^Cisco Systems, Inc$";
issuer_ou_pat[i]   = "^Intrusion Management System$";
subject_org_pat[i] = "^Cisco Systems, Inc$";
subject_ou_pat[i]  = "^Intrusion Management System$";
dev_type[i]        = "firewall";
confidence[i]      = 75;
i++;

name[i]            = "Cisco IPS";
issuer_ou_pat[i]   = "^IPS-[0-9]+";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^IPS-[0-9]+";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
dev_type[i]        = "embedded";
i++;

name[i]            = "Cisco Application Networking Manager";
confidence[i]      = 60;
issuer_ou_pat[i]   = "^Unknown$";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^Unknown$";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
dev_type[i]        = "embedded";
i++;

name[i]            = "Cisco NX-OS";
issuer_cn_pat[i]   = "^www.cisco.com/go/1000v";
issuer_ou_pat[i]   = "^SAVBU";
issuer_org_pat[i]  = "^Cisco Sytems Inc";                   # nb: this is indeed "Sytems"
subject_cn_pat[i]  = "^www.cisco.com/go/1000v";
subject_ou_pat[i]  = "^SAVBU";
subject_org_pat[i] = "^Cisco Sytems Inc";                   # nb: this is indeed "Sytems"
dev_type[i]        = "switch";
i++;

name[i]            = "Cisco NX-OS";
issuer_cn_pat[i]   = "^nxos";
issuer_ou_pat[i]   = "^nsstg";
issuer_org_pat[i]  = "^Cisco Systems Inc\.";
subject_cn_pat[i]  = "^nxos";
subject_ou_pat[i]  = "^nsstg";
subject_org_pat[i] = "^Cisco Systems Inc\.";
dev_type[i]        = "switch";
i++;

name[i]            = "CISCO VPN Concentrator";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
issuer_ou_pat[i]   = "^VPN .+ Concentrator";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^VPN .+ Concentrator";
dev_type[i]        = "VPN";
i++;

name[i]            = "CISCO VPN Hardware Client";
issuer_org_pat[i]  = "^Cisco Systems, Inc\.";
issuer_ou_pat[i]   = "^VPN .+ Hardware Client";
subject_org_pat[i] = "^Cisco Systems, Inc\.";
subject_ou_pat[i]  = "^VPN .+ Hardware Client";
dev_type[i]        = "VPN";
i++;

name[i]            = "Cisco IMC";
confidence[i]      = 75;
issuer_cn_pat[i]   = "^C-series CIMC";
#issuer_ou_pat[i]   = "PID:UCSC-C220-M4S SERIAL:FCH204576EH";
issuer_org_pat[i]  = "^Cisco";
subject_cn_pat[i]  = "^C-series CIMC";
#subject_ou_pat[i]  = "PID:UCSC-C220-M4S SERIAL:FCH204576EH";
subject_org_pat[i] = "^Cisco";
dev_type[i]        = "embedded";
i++;

name[i]            = "Citrix NetScaler";
issuer_cn_pat[i]   = "^default";
issuer_org_pat[i]  = "^Citrix ANG";
issuer_ou_pat[i]   = "^NS Internal";
subject_cn_pat[i]   = "^default";
subject_org_pat[i] = "^Citrix ANG";
subject_ou_pat[i]  = "^NS Internal";
dev_type[i]        = "embedded";
i++;

name[i]            = "Corero TopLayer IPS";
dev_type[i]        = "embedded";
issuer_cn_pat[i]   = "^Attack Mitigator IPS ";
issuer_org_pat[i]  = "^Corero Network Security, Inc\.";
issuer_ou_pat[i]   = "^support$";
subject_cn_pat[i]   = "^Attack Mitigator IPS ";
subject_org_pat[i] = "^Corero Network Security, Inc\.";
subject_ou_pat[i]  = "^support";
i++;

name[i]            = "HP 3PAR";
issuer_cn_pat[i]   = "^HP 3PAR HP_3PAR";
subject_cn_pat[i]  = "^HP 3PAR HP_3PAR";
dev_type[i]        = "embedded";
i++;

name[i]            = "HP JetDirect";
issuer_cn_pat[i]   = "^HP Jetdirect";
issuer_org_pat[i]  = "^Hewlett-Packard";
subject_cn_pat[i]  = "^HP Jetdirect";
subject_org_pat[i] = "^Hewlett-Packard";
dev_type[i]        = "printer";
i++;

name[i]            = "HP Access Point";
issuer_cn_pat[i]   = "^wireless\.hp\.local";
issuer_org_pat[i]  = "^Hewlett-Packard";
issuer_ou_pat[i]   = "^HP Networking";
subject_cn_pat[i]  = "^wireless\.hp\.local";
subject_org_pat[i] = "^Hewlett-Packard";
subject_ou_pat[i]  = "^HP Networking";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "Cyber Switching ePower PDU";
issuer_org_pat[i]  = "^Cyber Switching, Inc\.";
subject_org_pat[i] = "^Cyber Switching, Inc\.";
dev_type[i]        = "embedded";
i++;

# nb: there are 4 fingerprints for Dell DRAC / iDRAC
# iDRAC 8 / 9
name[i]            = "Dell iDRAC";
issuer_cn_pat[i]   = "^idrac-";
issuer_ou_pat[i]   = "^Remove Access Group";
issuer_org_pat[i]  = "^Dell Inc\.";
subject_cn_pat[i]  = "^idrac-";
subject_ou_pat[i]  = "^Remove Access Group";
subject_org_pat[i] = "^Dell Inc\.";
dev_type[i]        = "embedded";
i++;

name[i]            = "Dell DRAC";
issuer_cn_pat[i]   = "^cmcdefault";
issuer_ou_pat[i]   = "^OpenCMC Group";
issuer_org_pat[i]  = "^Dell Inc\.";
subject_cn_pat[i]  = "^cmcdefault";
subject_ou_pat[i]  = "^OpenCMC Group";
subject_org_pat[i] = "^Dell Inc\.";
dev_type[i]        = "embedded";
i ++;

name[i]           = "Dell iDRAC";
issuer_cn_pat[i]   = "(iDRAC[67]|DRAC5|RAC) default certificate";
issuer_org_pat[i]  = "^Dell (Computer|Inc\.)";
subject_cn_pat[i]  = "(iDRAC[67]|DRAC5|RAC) default certificate";
subject_org_pat[i] = "^Dell (Computer|Inc\.)";
dev_type[i]        = "embedded";
i ++;

name[i]            = "Dell iDRAC 6";
issuer_cn_pat[i]   = "^iDRACdefault[0-9A-F]+$";
issuer_ou_pat[i]   = "^iDRAC Group$";
issuer_org_pat[i]  = "^Dell Inc\.$";
subject_cn_pat[i]  = "^iDRACdefault[0-9A-F]+$";
subject_ou_pat[i]  = "^iDRAC Group$";
subject_org_pat[i] = "^Dell Inc\.$";
dev_type[i]        = "embedded";
i ++;

name[i]            = "SonicWALL";
confidence[i]      = 70;
issuer_org_pat[i]  = "^HTTPS Management Certificate for SonicWALL \(self-signed\)";
subject_org_pat[i] = "^HTTPS Management Certificate for SonicWALL \(self-signed\)";
dev_type[i]        = "embedded";
i++;

name[i]            = "Buffalo TeraStation NAS";
issuer_cn_pat[i]   = "^develop";
issuer_org_pat[i]  = "^BUFFALO INC\.";
issuer_ou_pat[i]   = "^NAS";
subject_cn_pat[i]  = "^develop";
subject_org_pat[i] = "^buffalo";
subject_ou_pat[i] = "^NAS";
dev_type[i]        = "embedded";
i++;

name[i]            = "Technicolor / Thomson Wireless Router";
issuer_cn_pat[i]   = "^Thomson TG[0-9]+";
issuer_org_pat[i]  = "^THOMSON$";
subject_cn_pat[i]  = "^Thomson TG[0-9]+";
subject_org_pat[i] = "^THOMSON$";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "Colubris MAP-330 AP";
issuer_cn_pat[i]   = "^wireless\.colubris.com";
issuer_org_pat[i]  = "^Colubris Networks Inc\.$";
subject_cn_pat[i]  = "^wireless\.colubris\.com";
subject_org_pat[i] = "^Colubris Networks Inc\.$";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "VMware ESX";
issuer_org_pat[i]  = "^VMware(, Inc| Installer)";
subject_org_pat[i] = "^VMware, Inc";
subject_ou_pat[i]  = "^VMware ESX Server (Default )?Certificate";
dev_type[i]        = "hypervisor";
i++;

name[i]            = "Linux Kernel 2.6 on an EMC Celerra Network Server";
issuer_org_pat[i]  = "^Celerra Certificate Authority";
issuer_cn_pat[i]   = "^emcnas_";
subject_org_pat[i] = "^Celerra Control Station Administrator";
dev_type[i]        = "embedded";
i++;

name[i]            = "Polycom Teleconferencing Device";
issuer_org_pat[i]  = "^Polycom Inc\.$";
issuer_ou_pat[i]   = "^Video Division$";
subject_org_pat[i] = "^Polycom Inc\.$";
subject_ou_pat[i]  = "^Video Division$";
dev_type[i]        = "embedded";
confidence[i]      = 75;
i++;

# Fingerprints for Oracle ILOM and Exadata.
# We need two for the former, and one for the latter.

name[i]            = "Oracle Integrated Lights Out Manager";
issuer_cn_pat[i]   = "^Oracle Integrated Lights Out Manager$";
issuer_org_pat[i]  = "^Oracle";
subject_cn_pat[i]  = "^Oracle Integrated Lights Out Manager$";
subject_org_pat[i] = "^Oracle";
dev_type[i]        = "embedded";
i++;

# Only Organization and Organization Unit seem available for these 2.

name[i]            = "Oracle Integrated Lights Out Manager";
issuer_org_pat[i]  = "^Oracle";
issuer_ou_pat[i]   = "^Oracle Integrated Lights Out Manager$";
subject_org_pat[i] = "^Oracle";
subject_ou_pat[i]  = "^Oracle Integrated Lights Out Manager";
dev_type[i]        = "embedded";
i++;

# Not sure on how to describe Exadata device type. embedded for now.

name[i]            = "Oracle Exadata" ;
issuer_org_pat[i]  = "^Oracle";
issuer_ou_pat[i]   = "^Oracle Exadata$";
subject_org_pat[i] = "^Oracle";
subject_ou_pat[i]  = "^Oracle Exadata$";
dev_type[i]        = "embedded";
i++;

name[i]            = "IBM Storwize";
issuer_cn_pat[i]   = "^2072$";
issuer_org_pat[i]  = "^IBM$";
subject_cn_pat[i]  = "^2072$";
subject_org_pat[i] = "^IBM$";
subject_ou_pat[i] = "^SSG$";
dev_type[i]        = "embedded";
confidence[i]      = 75;
i++;

name[i]            = "Isilon OneFS";
issuer_cn_pat[i]   = "^Isilon Systems";
issuer_org_pat[i]  = "^Isilon Systems, Inc\.$";
subject_cn_pat[i]  = "^Isilon Systems";
subject_org_pat[i] = "^Isilon Systems, Inc\.$";
dev_type[i]        = "embedded";
confidence[i]      = 75;
i++;

name[i]            = "Mandiant Intelligent Response appliance";
issuer_cn_pat[i]   = "^MIR_CA$";
issuer_org_pat[i]  = "^Mandiant$";
subject_org_pat[i] = "^Mandiant$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Mitel IP Communications Platform";
issuer_cn_pat[i]   = "^Mitel Networks ICP$";
issuer_ou_pat[i]   = "^VoIP Platforms$";
subject_cn_pat[i]  = "^Mitel Networks ICP CA$";
subject_ou_pat[i]  = "^VoIP Platforms$";
dev_type[i]        = "pbx";
i++;

name[i]            = "NETGEAR FVS318 ProSafe VPN Firewall";
issuer_org_pat[i]  = "^Netgear";
issuer_ou_pat[i]   = "^Certificate for FVS318 \(Self-Signed\)";
subject_org_pat[i] = "^Netgear";
subject_ou_pat[i]  = "^Certificate for FVS318 \(Self-Signed\)";
dev_type[i]        = "firewall";
i++;

name[i]            = "NETGEAR FVS318G ProSafe VPN Firewall";
issuer_org_pat[i]  = "^Netgear";
issuer_ou_pat[i]   = "^Certificate for FVS318G \(Self-Signed\)";
subject_org_pat[i] = "^Netgear";
subject_ou_pat[i]  = "^Certificate for FVS318G \(Self-Signed\)";
dev_type[i]        = "firewall";
i++;

name[i]            = "NETGEAR FVS318N ProSafe Wireless-N VPN Firewall";
issuer_org_pat[i]  = "^Netgear";
issuer_ou_pat[i]   = "^Certificate for FVS318N \(Self-Signed\)";
subject_org_pat[i] = "^Netgear";
subject_ou_pat[i]  = "^Certificate for FVS318N \(Self-Signed\)";
dev_type[i]        = "wireless-access-point";
i++;

name[i]            = "Palo Alto Networks PAN-OS";
issuer_org_pat[i]  = "^Palo Alto Networks$";
issuer_ou_pat[i]   = "^Support$";
subject_org_pat[i] = "^Palo Alto Networks$";
subject_ou_pat[i]  = "^Support$";
dev_type[i]        = "firewall";
i++;

name[i]            = "PelcoLinux";
issuer_cn_pat[i]   = "^localhost$";
issuer_org_pat[i]  = "^Pelco$";
subject_cn_pat[i]  = "^localhost$";
subject_org_pat[i] = "^Pelco$";
dev_type[i]        = "embedded";
i++;

name[i]            = "HP Integrated Lights Out";
issuer_cn_pat[i]   = "^iLO Default Issuer";
issuer_org_pat[i]  = "^Hewlett-Packard Company";
subject_cn_pat[i]  = "^iLO Default Issuer";
subject_org_pat[i] = "^Hewlett-Packard Company";
dev_type[i]        = "embedded";
i++;

name[i]            = "HP Onboard Administrator";
issuer_org_pat[i]  = "^Hewlett-Packard$";
issuer_ou_pat[i]   = "^Onboard Administrator$";
subject_org_pat[i] = "^Hewlett-Packard$";
subject_ou_pat[i]  = "^Onboard Administrator$";
dev_type[i]        = "embedded";
i++;

name[i]            = "EMC CLARiiON";
issuer_org_pat[i]  = "^EMC$";
issuer_ou_pat[i]   = "^CLARiiON$";
subject_org_pat[i] = "^EMC$";
subject_ou_pat[i]  = "^CLARiiON$";
dev_type[i]        = "embedded";
confidence[i]      = 85;
i++;

name[i]            = "EMC Data Domain OS";
issuer_org_pat[i]  = "^Valued Datadomain Customer$";
issuer_ou_pat[i]   = "^Root CA$";
subject_org_pat[i] = "^Valued DataDomain customer$";
subject_ou_pat[i]  = "^Host Certificate";
dev_type[i]        = "embedded";
confidence[i]      = 85;
i++;

name[i]            = "Net Optics Director";
subject_cn_pat[i]  = "Director\.netoptics\.com";
issuer_org_pat[i]  = "^Net Optics, Inc\.$";
subject_org_pat[i] = "^Net Optics, Inc\.$";
dev_type[i]        = "switch";
i++;

name[i]            = "FortiOS on Fortinet FortiGate";
dev_type[i]        = "firewall";
issuer_cn_pat[i]   = "^support$";
issuer_org_pat[i]  = "^Fortinet$";
issuer_ou_pat[i]   = "^Certificate Authority$";
subject_org_pat[i] = "^Fortinet$";
subject_ou_pat[i]  = "^FortiGate$";
i++;

name[i]            = "Cisco Video Communication Server";
confidence[i]      = 65;
dev_type[i]        = "embedded";
issuer_cn_pat[i]   = "^TANDBERG$";
issuer_org_pat[i]  = "^TANDBERG ASA$";
issuer_ou_pat[i]   = "^R&D$";
subject_cn_pat[i]  = "^TANDBERG$";
subject_org_pat[i] = "^TANDBERG ASA$";
subject_ou_pat[i]  = "^R&D$";
i++;

name[i]            = "PCoIP Zero Client";
confidence[i]      = 80;
dev_type[i]        = "embedded";
issuer_cn_pat[i]   = "^PCoIP Root CA$";
issuer_ou_pat[i]   = "^PCoIP Root$";
subject_ou_pat[i]  = "^PCoIP Device$";
i++;

name[i]            = "Silver Peak Systems";
dev_type[i]        = "embedded";
issuer_org_pat[i]  = "^Silver Peak Systems Inc";
issuer_ou_pat[i]   = "^Networking Appliance";
subject_org_pat[i] = "^Silver Peak Systems Inc";
subject_ou_pat[i] = "^Networking Appliance";
i++;

name[i]            = "Juniper Junos Space";
dev_type[i]        = "embedded";
issuer_org_pat[i]  = "^Juniper Networks, Inc.$";
issuer_ou_pat[i]   = "^Junos Space$";
subject_org_pat[i] = "^Juniper Networks, Inc.$";
subject_ou_pat[i]  = "^Junos Space$";
i++;

name[i]            = "QNAP QTS on a TS-Series NAS";
issuer_cn_pat[i]   = "^TS Series NAS";
issuer_org_pat[i]  = "^QNAP Systems Inc\.";
issuer_ou_pat[i]   = "^NAS";
subject_cn_pat[i]  = "^TS Series NAS";
subject_org_pat[i] = "^QNAP Systems Inc\.";
subject_ou_pat[i] = "^NAS";
dev_type[i]        = "embedded";
i++;

name[i]            = "Lantronix SLC";
issuer_cn_pat[i]   = "^SLC$";
issuer_org_pat[i]  = "^Lantronix$";
subject_cn_pat[i]  = "^SLC$";
subject_org_pat[i] = "^Lantronix$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Siemens PLC";
issuer_cn_pat[i]   = "^Siemens Root CA$";
issuer_org_pat[i]  = "^Siemens$";
subject_cn_pat[i]  = "^jupps$";
subject_org_pat[i] = "^Siemens AGs$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Grandstream PBX";
issuer_cn_pat[i]   = "^Grandstream$";
issuer_org_pat[i]  = "^Grandstream Networks, Inc$";
subject_cn_pat[i]  = "^Grandstream$";
subject_org_pat[i] = "^Grandstream Networks, Inc$";
dev_type[i]        = "pbx";
i++;


name[i]            = "Barco WePresent";
issuer_cn_pat[i]   = "^barco.com$";
issuer_org_pat[i]  = "^Barco Limited$";
issuer_ou_pat[i]   = "^Application Engineering Team$";
subject_cn_pat[i]  = "^barco.com$";
subject_org_pat[i] = "^Barco Limited$";
subject_ou_pat[i]  = "^Application Engineering Team$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Extron ShareLink";
issuer_cn_pat[i]   = "^AWiND$";
issuer_org_pat[i]  = "^AWiND$";
issuer_ou_pat[i]   = "^Embedded$";
subject_cn_pat[i]  = "^AWiND$";
subject_org_pat[i] = "^AWiND$";
subject_ou_pat[i]  = "^Embedded$";
dev_type[i]        = "embedded";
i++;

name[i]            = "pfSense";
issuer_cn_pat[i]   = "^pfSense-";
issuer_org_pat[i]  = "^pfSense webConfigurator Self-Signed Certificate$";
subject_cn_pat[i]  = "^pfSense-";
subject_org_pat[i] = "^pfSense webConfigurator Self-Signed Certificate$";
dev_type[i]        = "firewall";
i++;

name[i]            = "Alcatel-Lucent Appliance";
confidence[i]      = 75;
issuer_cn_pat[i]   = "^webview$";
issuer_org_pat[i]  = "^Alcatel-Lucent$";
subject_cn_pat[i]  = "^webview$";
subject_org_pat[i] = "^Alcatel-Lucent$";
subject_ou_pat[i] = "^ESD$";
dev_type[i]        = "switch";
i++;

name[i]            = "Symantec Reporter";
confidence[i]      = 70;
issuer_org_pat[i]  = "^Symantec Reporter$";
issuer_ou_pat[i]   = "^0801482058$";
subject_org_pat[i] = "^Symantec Reporter$";
subject_ou_pat[i]  = "^0801482058$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Symantec Content Analysis";
confidence[i]      = 70;
issuer_org_pat[i]  = "^Symantec Corporation$";
subject_org_pat[i] = "^Symantec Corporation$";
subject_ou_pat[i]  = "^Content Analysis$";
issuer_ou_pat[i]   = "^Content Analysis$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Quest DR Series Appliance";
issuer_org_pat[i]  = "^DR Series$";
issuer_ou_pat[i]   = "^DR Series$";
subject_org_pat[i] = "^DR Series$";
subject_ou_pat[i]  = "^DR Series$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Super Micro";
confidence[i]      = 75;
issuer_cn_pat[i]   = "^IPMI$";
# should match both 'Super Micro Computer' and 'Super Micro Computer Inc.'
issuer_org_pat[i]  = "^Super Micro Computer";
# should match both 'Software' and 'Software Department'
issuer_ou_pat[i]   = "^Software";
subject_cn_pat[i]  = "^IPMI$";
# should match both 'Super Micro Computer' and 'Super Micro Computer Inc.'
subject_org_pat[i] = "^Super Micro Computer";
# should match both 'Software' and 'Software Department'
subject_ou_pat[i]  = "^Software";
dev_type[i]        = "embedded";
i++;

name[i]            = "Zinwave Series 3000 DAS";
issuer_cn_pat[i]   = "^zinwave$";
issuer_org_pat[i]  = "^ZinWave Ltd$";
issuer_ou_pat[i]   = "^ZinWave Ltd$";
subject_cn_pat[i]  = "^zinwave$";
subject_org_pat[i] = "^ZinWave Ltd$";
subject_ou_pat[i]  = "^ZinWave Ltd$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Symantec Management Center";
issuer_org_pat[i]  = "^Blue Coat Management Center$";
subject_org_pat[i] = "^Blue Coat Management Center$";
dev_type[i]        = "embedded";
i++;

name[i]            = "Veritas NetBackup Appliance";
confidence[i]      = 75; # Lower confidence since 'NetBackup' is not present
issuer_org_pat[i]  = "^Veritas Technologies LLC$";
issuer_ou_pat[i]   = "^Appliance Solutions$";
subject_org_pat[i] = "^Veritas Technologies LLC$";
subject_ou_pat[i]  = "^Appliance Solutions$";
dev_type[i]        = "embedded";
i++;

var default_confidence = 90;
var default_type = "embedded";
var n = i;

var fingerprint = "";

var cert, sha1, tbs, issuer_seq, subject_seq, issuer;
var o, subject, issuer_cn_pat, device_type;

foreach var port (ports)
{
  if (!get_port_state(port)) continue;

  cert = get_server_cert(port:port, encoding:"der");
  if (isnull(cert)) continue;
  sha1 = hexstr(SHA1(cert));

  cert = parse_der_cert(cert:cert);
  if (isnull(cert)) continue;

  tbs = cert["tbsCertificate"];
  issuer_seq = tbs["issuer"];
  subject_seq = tbs["subject"];

  issuer = make_array();
  foreach var seq (issuer_seq)
  {
    o = oid_name[seq[0]];
    if (!isnull(o)) issuer[o] = seq[1];
  }

  subject = make_array();
  foreach seq (subject_seq)
  {
    o = oid_name[seq[0]];
    if (!isnull(o)) subject[o] = seq[1];
  }

  if ( strlen(fingerprint) < 256 )
  {
   if (issuer["Common Name"])        fingerprint += "i/CN:" + issuer["Common Name"];
   if (issuer["Organization"])       fingerprint += "i/O:" + issuer["Organization"];
   if (issuer["Organization Unit"])  fingerprint += "i/OU:" + issuer["Organization Unit"];
   if (subject["Common Name"])       fingerprint += "s/CN:" + subject["Common Name"];
   if (subject["Organization"])      fingerprint += "s/O:" + subject["Organization"];
   if (subject["Organization Unit"]) fingerprint += "s/OU:" + subject["Organization Unit"];
   fingerprint += '\n' + sha1 + '\n';
  }

  for (i=0; i<n; i++)
  {
    if (
      (
        !issuer_cn_pat[i] ||
        (issuer["Common Name"] && pregmatch(pattern:issuer_cn_pat[i], string:issuer["Common Name"]))
      ) &&
      (
        !issuer_org_pat[i] ||
        (issuer["Organization"] && pregmatch(pattern:issuer_org_pat[i], string:issuer["Organization"]))
      ) &&
      (
        !issuer_ou_pat[i] ||
        (issuer["Organization Unit"] && pregmatch(pattern:issuer_ou_pat[i], string:issuer["Organization Unit"]))
      ) &&
      (
        !subject_cn_pat[i] ||
        (subject["Common Name"] && pregmatch(pattern:subject_cn_pat[i], string:subject["Common Name"]))
      ) &&
      (
        !subject_org_pat[i] ||
        (subject["Organization"] && pregmatch(pattern:subject_org_pat[i], string:subject["Organization"]))
      ) &&
      (
        !subject_ou_pat[i] ||
        (subject["Organization Unit"] && pregmatch(pattern:subject_ou_pat[i], string:subject["Organization Unit"]))
      )
    )
    {
      if (confidence[i]) confidence = confidence[i];
      else confidence = default_confidence;

      if (dev_type[i]) device_type = dev_type[i];
      else device_type = default_type;

      set_kb_item(name:"Host/OS/SSLcert", value:name[i]);
      set_kb_item(name:"Host/OS/SSLcert/Confidence", value:confidence);
      set_kb_item(name:"Host/OS/SSLcert/Type", value:dev_type[i]);
      exit(0);
    }
  }
}
if ( strlen(fingerprint) > 0 ) set_kb_item(name:"Host/OS/SSLcert/Fingerprint", value:fingerprint);
exit(0, "Nessus was not able to identify the OS from any SSL certificates it uses.");
