#TRUSTED 8acbf556b264618c8b841e2986b4e1bad682afa43298dda899cbb77edb994a1c37c76d1935c3fd3e5b661bbdce2eadaf8488f2dbd76ab134dbe3bc9e9fac861cc5eac75dd33cb0535af0464beb5379b1d3b085c9b418d321e17a12d7f149f444f73966ed5c3a8f225eacb8f1635e873f78e22d28d47f263cb2bacdb2523fe05a758de5dc5063fd2cc7fdb0591e07a88e9441d6e1be8d0b4f24a15e22f60eb3aacf4e580eee0eefcca0da6f61bcaf43cdfa28de89013a9ab13cbfc703658b4126d6908e6de1d8ad62b13bbc88bd91c93dda07b54d1d138b4410d5854fba716aa3bb19490e5ccd87e24bbdf223ae4af3d8c8b8a1df00cefc9204945b39dd4cc1361f7799f696b7dc7457c31e81068398763918adbaf99389d3ea05f8b3e41b5790f25955d518c1bc58bae2946a90e99960460a9475d78b78cf3d2a4ebcba5bf39db9241172db52970e8f6c01f9bc98302e6990206ca236e877f4cf3ecdee169c53d8bb4cb84bfff67f0ec073e2919882bce7f6af76ff60b2e9fddd5f99f29b82675bbf6f67fd7568b8ed40b03d704c3cab344ad6111a632622b5ded555bad1a5d715c506725d7992feaee219df69ea55431a8601f5137f1e6229e5157e090e20bb7882a25e544c38c67e7cd45e3cf96d678891d73352a7f5acab271354f974b9f59be59bdbf236bf45fcbac515eac21d4cc9c3a0ba95ff2bbefebdf298118d0e75
#TRUST-RSA-SHA256 173a87562cf24e2364e62902dc466470ec6b77cb2f4d7777c6fb0e9e92990b7ca13ec52213fb5db9a4b586a5324c244f03f06c9e9a43aae485f8471ac197b290f3095e8d70f004119d19f075eac5decf872c6ef855db15011e6b79a70f8e36d46cc3d47a05642dd761c27409494765bf308d8b7781db63db6b46dd1ca54aee146d90c7645d48f27e035970f50cac22a6edcaa5acec1f68ffea91d97c59a750df891d7ab0b73707731cd7fed0e105f1a8521ebf66763ad994bee786a434ecb9ec25d8cbac09e7e6f04582e820b1e3d9942bfd897ce05552383c59baa331fbb5170024d9a954228b18e00a44796144ee7dfb78b067faf6133c9249c9c02d55299e9cabc63e7d5bbc3e45b70ff1c738df305905cb3660ccb0bf3425abc2742d5414fa6fb6c6e27e47d13ac1a530739e7479f38d17e9b142583bb698dfbde49ecad41adf451a4d3d6de3137f51e5f8e26671c9832d063cc587117f2b445c7e4fb33127df5a28eba5d76835eb5ea198cf18a400e4b8c8b9f12464ea4ce0f4838fd5370967c1dc7bcba7e2d1644d8fb3c98032cf91fbf21b556e70ca85789db58cf6caebfba4f5a0ab8314252d0e389303006363a3ff3efbd2e643f525df366a759227e68dfd6c2a12fb8cf3ac0e0f5427b9ee050eea8dad48866ad129c73a416547fd68a8982a7ccc2246ff0d56ba7f28f04801785b27cd2ad844a3a964660b0e2aab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(110723);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/19");

  script_xref(name:"IAVB", value:"0001-B-0504");

  script_name(english:"Target Credential Status by Authentication Protocol - No Credentials Provided");
  script_summary(english:"Reports protocols that have no credentials provided in the scan policy.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to find common ports used for local checks,
however, no credentials were provided in the scan policy.");
  script_set_attribute(attribute:"description", value:
"Nessus was not able to successfully authenticate directly to the
remote target on an available authentication protocol. Nessus was
able to connect to the remote port and identify that the service
running on the port supports an authentication protocol, but Nessus
failed to authenticate to the remote service using the provided
credentials. There may have been a protocol failure that prevented
authentication from being attempted or all of the provided credentials
for the authentication protocol may be invalid. See plugin output for
error details.

Please note the following :

- This plugin reports per protocol, so it is possible for
  valid credentials to be provided for one protocol and not
  another. For example, authentication may succeed via SSH
  but fail via SMB, while no credentials were provided for
  an available SNMP service.

- Providing valid credentials for all available
  authentication protocols may improve scan coverage, but
  the value of successful authentication for a given
  protocol may vary from target to target depending upon
  what data (if any) is gathered from the target via that
  protocol. For example, successful authentication via SSH
  is more valuable for Linux targets than for Windows
  targets, and likewise successful authentication via SMB
  is more valuable for Windows targets than for Linux
  targets.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/27");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  # No dependencies, since this is an ACT_END plugin
  exit(0);
}

include("lcx.inc");

global_var report = '';
global_var creds_found = FALSE;

if(get_kb_item('Host/local_checks_enabled'))
  exit(0, 'Local checks have been enabled on the host.');

function check_ssh()
{
  var ssh, ssh_ports_string, plural, ssh_cred, ssh_cred_list, os; 
  var ssh_sudo, auth_methods, auth_methods_used, credential_repos;

  os = get_kb_item('Host/OS');
  
  # Don't report if os is windows or we aren't paranoid and don't know the OS 
  if((report_paranoia < 2 && !os) || "Windows" >< os)
    return NULL;
  
  ssh = get_service_port_list(svc:'ssh');
  
  if(ssh && max_index(ssh) > 0)
  {
    ssh_ports_string = '';
    
    if(max_index(ssh) > 1)
    {
      plural = 's';
      ssh_ports_string = join(ssh, sep:', ');
    }
    else
    {
      plural = '';
      ssh_ports_string += ssh[0];
    }
    
    # remove leading space and trailing comma
    ssh_cred = get_kb_item("Secret/SSH/login");
    ssh_sudo = get_kb_item("Secret/SSH/sudo_method");
    ssh_cred_list = get_kb_list('Secret/SSH/*/login');

    # Check if scan is configured to try and retrieve creds from PAM
    auth_methods = make_list(get_kb_list("target/auth/method"));
    credential_repos = make_list('Thycotic', 
                                 'BeyondTrust', 
                                 'Centrify', 
                                 'Lieberman',
                                 'HashiCorp', 
                                 'Arcon',
                                 'CyberArk', 
                                 'CyberArk REST', 
                                 'LM Hash', 
                                 'NTLM Hash');
    auth_methods_used = collib::intersection(credential_repos, auth_methods);

    # When no SSH credentials are provided root may be the default login and all sudo options may be set
    if ((empty_or_null(ssh_cred) || ssh_cred == "root") &&
        (empty_or_null(ssh_sudo) || ssh_sudo == "Nothing;sudo;su;su+sudo;dzdo;pbrun;Cisco 'enable'") &&
        !ssh_cred_list && empty_or_null(auth_methods_used))
    {
      report += 'SSH was detected on port'+plural+' '+ssh_ports_string+' but no credentials were' +
        ' provided.\nSSH local checks were not enabled.\n\n';

      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
        "Credentials were not provided for detected SSH service.");
    }

    else
      creds_found = TRUE;
  }

}

function check_smb()
{
  var smb, smb_ports_string, plural, smb_cred_list, os, credential_repos, auth_methods, auth_methods_used;
  os = get_kb_item('Host/OS');
  # Don't report if os is not windows or we aren't paranoid and don't know the OS
  if((report_paranoia < 2 && !os) || "Windows" >!< os)
    return NULL;
  smb = get_kb_list('SMB/transport');
  
  # remove leading space and trailing comma
  if(smb && max_index(keys(smb)) > 0)
  {
    smb_ports_string = '';
    if(max_index(keys(smb)) > 1)
    {
      plural = 's';
      smb_ports_string = join(smb, sep:', ');
    }
    else
    {
      plural = '';
      smb_ports_string += smb['SMB/transport'];
    }
 
    # SMB/login_filled means credential using "Password" auth methods
    # target/auth/method for all other auth methods
    smb_cred_list = get_kb_list("SMB/login_filled/*");
    auth_methods = make_list(get_kb_list("target/auth/method"));
    credential_repos = make_list('Thycotic', 
                                 'BeyondTrust', 
                                 'Centrify', 
                                 'Lieberman', 
                                 'HashiCorp', 
                                 'Arcon', 
                                 'CyberArk', 
                                 'CyberArk REST', 
                                 'LM Hash', 
                                 'NTLM Hash');
    auth_methods_used = collib::intersection(credential_repos, auth_methods);
 
    if (empty_or_null(smb_cred_list) && empty_or_null(auth_methods_used))
    {
      report += 'SMB was detected on port'+plural+' '+smb_ports_string+' but no credentials were' +
        ' provided.\nSMB local checks were not enabled.\n\n';
      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
        "Credentials were not provided for detected SMB service.");
    }
    else
      creds_found = TRUE;
  }

}

function check_snmp()
{
  var snmp, snmp_ports_string, plural, snmpv3_user, snmp_comm_names, os, snmp_default_port;
  os = get_kb_item('Host/OS');
  # Don't report if os is not windows or we aren't paranoid and don't know the OS
  #if((report_paranoia < 2 && !os) || os >!< "Windows")
  #  return NULL;
  snmp = get_service_port_list(svc:'snmp');
  snmpv3_user = get_kb_item("SNMP/v3/username");
  snmp_comm_names = get_kb_list("SNMP/community_name/*"); # < v3
  snmp_default_port = get_kb_item('Ports/udp/161');
  plural = '';
  if(!snmp && !snmp_default_port)
    return NULL;
  if(max_index(snmp) > 1)
  {
    plural = 's';
    snmp_ports_string = join(snmp, sep:', ');
  }
  else if(!snmp)
    snmp_ports_string = '161';
  if (
      max_index(keys(snmp_comm_names)) == 1 &&
      snmp_comm_names['SNMP/community_name/0'] == 'public' &&
      get_kb_item('SNMP/auth_failed') && 
      !snmpv3_user
    )
  {
    report += 'SNMP was detected on port'+plural+' '+snmp_ports_string+' but no credentials were' +
      ' provided.\nSNMP local checks were not enabled.\n\n';
      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
        "Credentials were not provided for detected SNMP service.");
  }
    else
      creds_found = TRUE;

}

function check_panweb()
{
  if (!get_kb_item("www/panweb")) return NULL;
  if (get_kb_item("Secret/Palo_Alto/Firewall/Login"))
  {
    creds_found = TRUE;
    return NULL;
  }
  var port_str = "";
  var kbs = get_kb_list("www/*/palo_alto_panos");
  if (!isnull(kbs))
  {
    kbs = keys(kbs);
    var s = "";
    if (max_index(kbs) > 1) s = "s";
    port_str = " on port" + s + " ";
    var ports = [];
    foreach var kb (kbs)
    {
      kb -= "www/";
      kb -= "/palo_alto_panos";
      ports[max_index(ports)] = kb;
    }
    port_str += join(ports, sep:', ');
  }

  report +=
    'Palo Alto Networks PAN-OS Web UI was detected' + port_str +
    ' but\nno credentials were provided.' +
    '\nPAN-OS local checks were not enabled.\n\n';

  lcx::log_issue(type:lcx::ISSUES_INFO, msg:
    "Credentials were not provided for detected PAN-OS WebUI service.");

  return NULL;
}

#function check_vsphere()
#{
#  var kbs = get_kb_list("Host/VMware/vsphere");
#  if (isnull(kbs)) return NULL;
#
#  # Check for an open vsphere port that supports HTTPS
#  var encaps, ports = [];
#  foreach var p (make_list(kbs))
#  {
#    if (!get_port_state(p)) continue;
#    encaps = get_kb_item("Transports/TCP/"+p);
#    if (encaps == ENCAPS_IP) continue;
#    ports[max_index(ports)] = p;
#  }
#  if (max_index(ports) < 1) return NULL;
#
#  if (get_kb_item("Secret/VMware/login"))
#  {
#    creds_found = TRUE;
#    return NULL;
#  }
#
#  var a = "A";
#  var s = "";
#  var was = " was";
#  if (max_index(ports) > 1)
#  {
#    a = "";
#    s = "s";
#    was = " were";
#  }
#  ports = " " + join(make_list(ports), sep:', ');
#
#  report +=
#    a+' VMware ESX/ESXi SOAP API webserver'+s+was+' detected on port'+s + ports +
#    '\nbut no credentials were provided.' +
#    '\nESX/ESXi local checks were not enabled.\n\n';
#  lcx::log_issue(type:lcx::ISSUES_INFO, msg:
#    "Credentials were not provided for detected ESX/ESXi SOAP API.");
#
#  return NULL;
#}

#function check_vcenter()
#{
#  if (get_kb_item("Host/VMWare/found"))
#  {
#    if (empty_or_null(get_kb_item("Host/VMware/esxcli_software_vibs")) && empty_or_null(get_kb_item("Host/VMware/esxupdate")))
#    {
#      report +=
#        'VCenter detected this ESX/ESXi host but did not return patch details.' +
#        '\nWithout these details vulnerability data may be missing or inaccurate' +
#        '\nCheck your VCenter server for connectivity or licensing issues\n\n';
#      lcx::log_issue(type:lcx::ISSUES_INFO, msg:
#        "VIBS were not provided for detected ESX/ESXi Host.");
#    }
#  }
#  return NULL;
#}

check_ssh();
check_smb();
check_snmp();
check_panweb();
# Disabling these because the check is not correct - jhammack
# It is triggering vCenter as ESXi and saying no creds/etc
#check_vsphere();
#check_vcenter();

if(strlen(report) > 0)
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
else if(creds_found)
{
  if (get_kb_list("Host/Auth/*/Failure") && !get_kb_list("Host/Auth/*/Success"))
    exit(0, 'Services supporting local checks were found, but credentials failed.');
  else exit(0, 'Services supporting local checks were found, but local checks were not enabled.');
}
else
  exit(0, 'No services supporting local checks were found on the host.');
