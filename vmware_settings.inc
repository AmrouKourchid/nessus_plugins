#TRUSTED 66bb298fdf018878b0e7bbad1593e5ae30a48cdcbe3a9b271e544df0e4820b8e0d5bdbb13cebb44f3624cbf68f7243520f0f0fcafb8acd3af65c996bb09d579d57afc595bd7fa74dc0aaeb4494b3a2bf5586f8a47292e62f472a29fcae06ee49289531793abb56d891ee3236a5599be000c9ea499bf20e48ce51919623e18ca508a419a42c2017156e6b144badecee7182b725421df0d0faeed947a8db1ed5b407011411f503ef3fa90a596c57aaf6726832177d907c11b27baffe028d149f5199098d9b6eefd29c799156a2760b678ee67a6f90c55a5d918816acbaaeb7fd30ec073f43d91b9097f9589276056e8191788fd0770715fec1efe9343f88b8393986d1e34449189537d29bba9678ee1fc85d7c56242e561dca3a88f57b4f61cee8b6279f6ccdcbfe6a4e29f8c69f63a45d2d0b50204f31023320c6481fe9512f02ce034e7ef71a2d85b07d9c45c961ec2a556c9255d3bdffdc5c6df7594f9258c043c8f8eae7b2f07767019cf77aef8c6c75248a918f1b5b8af70fcd3a6d052ef43913915e35c61d1bd88a90519b1905a313d13d056061e7d167edd2e1bc84a47f7b477168fa460284e8ff3a4ffd92133f09ca29d51ad69e29190d4d33e80cede632b937bb88144e4a06a4b745e68854815f02796f7d1b45669fd76eb2e164cd43b7bc49f09562966e03d0b428f035b98573d59da7e1122d4e72cd6cb91ef21c18
#TRUST-RSA-SHA256 5018b85e1ca3e4fe3dabb183b97539489125f330db2059feb5ca6b4798585edd22c56ccdb8524d549911f42758a64f9ac0859de2454202741f88b94d7aed5e47b69fe2e5f7384be3c9967c450e97b25a9b6c76df012f84dfe1295880229bdb5c060822db6a4430d828b5d8e08e49b96048625d8e1c0118a0e41a3970f574c6b14133cb587483c022b1f482aa15f33d231fa7219e045bff6ce2e648cca0201328913f5a523c8fe6e628bed28b414ad947507571fa84d57e8851a822113c1f1252ad3cc4edf43d65927ddd113e0f5b9124cf805f88546c25dcf72dc83199b2774a6eadb7320294c804d3399622a5f130d99416e2ab2e158c0cc908ad7e919801e70dfd7d4741761a281063ca6ef6739ed901494d2ba0eac6ce9c282cf1ad72206a73abcc7b8741555ba3b474101fde577493f6c45822c5f25dabf7a27c7c287fdad683dff4909f84ed9cc53b077fa4b4c862eb812d122b40e086c5800ae1e190611b953f7dcb1bc421e8eefd36c59d8c2a783407bd8187cc9061a9eca08e94f776608ac4252737a2aefb8cb0d611272887c696fc79393108e77617aa1d592945d5b6cef75aadaf42d97de3f1ed34fa96c06bcab2adc002c025a64ee8925aa79606159705f11cbb425848f0f069b46e198006abdc439676e3d5d3c8534a18d7722bf11e03001be8e82ba6c947bc18a4a466c64f5abc2f9dc10d444e4efb8bf1ade3

##
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
##

include("cyberark.inc");
include("compat_shared.inc");
#pragma static(include:false)
include("integrations_common.inc");

global_var VMWARE_CREDENTIALS_LIMIT = 5;
global_var VMWARE_CRED_TYPE_SOAP = 1;
global_var VMWARE_CRED_TYPE_VCENTER = 2;

##
# Store vmware credentials in the KB
#
# @param [creds:list] list of arrays, where each array contains a different
# credential (login/username and password)
##
function store_vmware_credentials(creds)
{
  var item, k;

  foreach item (creds)
  {
    foreach k (keys(item))
    {
      replace_kb_item(name:k, value:item[k]);
    }
  }
}

##
# Retrieve VMware vcenter (multiple) credentials from the UI
#
# @return list of the vmware vcenter credentials
##
function retrieve_vcenter_credentials()
{
  var i, vmware_prefix, vmware_postfix, username, passwd, creds, result_array, pam_creds, auth_method,
  kb_index, username_key, vmware_key, host, port, ssl, ssl_verify, auto_discover_esxi, auto_discover_vm, report_vcenter_vms;
  
  creds = make_list();

  # "VMware vCenter SOAP API Settings[password]:VMware vCenter password (unsafe!) :" 
  # KB entry like Secret/vCenter/username
  vmware_key = "vCenter";
  username_key = "username";


  for (i = 0; i < VMWARE_CREDENTIALS_LIMIT; i++)
  {
    # create prefixes
    if (i > 0)
    {
      vmware_prefix = "Additional ";
      vmware_postfix = " ("+i+") : ";
      kb_index = "/"+(i-1)+"/";
    }
    else
    {
      vmware_prefix = ""; # no prefix
      vmware_postfix = " : ";
      kb_index = "/";
    }

    # PAM Support only available for VMware vCenter API settings and not VMware vCenter SOAP API settings.
    # auth_method should not be null as it creates a nessusd.dump error when setting NULL kb_item, so we should set to "Username" if NULL.
    # This means the SOAP API setting are in use.
    auth_method = script_get_preference(vmware_prefix + "vCenter Authentication Method" + vmware_postfix);
    if (isnull(auth_method))
    {
      auth_method = "Username";
    }
    username = retrieve_script_preference(pref:vmware_prefix + "VMware vCenter user name" + vmware_postfix);
    pam_creds = _get_creds_from_pam(username:username, prefix:vmware_prefix, postfix:vmware_postfix, auth_method:auth_method);

    # If using PAM for vCenter Authentication
    if ("Username" >!< auth_method && !isnull(auth_method))
    {
      username = pam_creds.username;
    }
    
    # check username is not null
    if (strlen(username) < 1)
    {
      if (COMMAND_LINE)
      {
        break;
      }
      
      if (i <= VMWARE_CREDENTIALS_LIMIT)
      {
        continue;
      }
      else
      {
        break;
      }
    }

    # retrieve password
    if ("Username" >< auth_method)
    {
      passwd = retrieve_script_preference(pref:vmware_prefix + "VMware vCenter password" + vmware_postfix);

      if (isnull(passwd))
      {
        passwd = retrieve_script_preference(pref:vmware_prefix + "VMware vCenter SOAP API Settings[password]:VMware vCenter password (unsafe!)" + vmware_postfix);
      }
    }
    else
    {
      passwd = pam_creds.password;
    }

    host = retrieve_script_preference(pref:vmware_prefix + "VMware vCenter host" + vmware_postfix);
    port = retrieve_script_preference(pref:vmware_prefix + "VMware vCenter port" + vmware_postfix);

    ssl = retrieve_script_preference(pref:vmware_prefix+"SSL"+vmware_postfix);
    ssl_verify = retrieve_script_preference(pref:vmware_prefix + "Verify SSL Certificate" + vmware_postfix);

    auto_discover_esxi = retrieve_script_preference(pref:vmware_prefix + "Auto Discover Managed ESXi Hosts" + vmware_postfix);
    auto_discover_vm = retrieve_script_preference(pref:vmware_prefix + "Auto Discover Managed Virtual Machines" + vmware_postfix);
    report_vcenter_vms = retrieve_script_preference(pref:vmware_prefix + "Report Active and Inactive Virtual Machines" + vmware_postfix);

    if (!host && !port && !username && !passwd)
    {
      exit(0, "VMware vCenter API is not configured.");
    }
    else if (!host || !port || !username || !passwd)
    {
      exit(0, "One or more VMware vCenter API settings is not configured.");
    }

    if (ssl && "yes" >< ssl)
    {
      ssl = TRUE;
    }
    else
    {
      ssl = FALSE;
    }

    if (ssl_verify && "yes" >< ssl_verify)
    {
      ssl_verify = TRUE;
    }
    else
    {
      ssl_verify = FALSE;
    }

    if (auto_discover_esxi && "yes" >< auto_discover_esxi)
    {
      auto_discover_esxi = TRUE;
    }
    else
    {
      auto_discover_esxi = FALSE;
    }

    if (auto_discover_vm && "yes" >< auto_discover_vm)
    {
      auto_discover_vm = TRUE;
    }
    else
    {
      auto_discover_vm = FALSE;
    }

    # report_vcenter_vms should only be false if it is explicitly set
    # to 'no'. In other cases (for example, where the preference may not
    # yet exist in the UI) we should report vcenter VMs, as this was the
    # default behavior before this preference was introduced.
    if (report_vcenter_vms && "no" >< report_vcenter_vms)
    {
      report_vcenter_vms = FALSE;
    }
    else
    {
      report_vcenter_vms = TRUE;
    }

    # store data in the creds list
    result_array = make_array("Secret/"+vmware_key+kb_index+username_key, username,
                              "Secret/"+vmware_key+kb_index+"password", passwd,
                              "Host/"+vmware_key+kb_index+"host", host,
                              "Host/"+vmware_key+kb_index+"port", port,
                              "Host/"+vmware_key+kb_index+"ssl", ssl,
                              "Host/"+vmware_key+kb_index+"ssl_verify", ssl_verify,
                              "Host/"+vmware_key+kb_index+"auto_discover_esxi", auto_discover_esxi,
                              "Host/"+vmware_key+kb_index+"auto_discover_vm", auto_discover_vm,
                              "Host/"+vmware_key+kb_index+"report_vcenter_vms", report_vcenter_vms,
                              "Host/"+vmware_key+kb_index+"auth_method", auth_method
    );

    creds[i] = result_array;
  }

  return creds;
}

##
# Retrieve VMware vSphere (ESXi) (multiple) credentials from the UI
#
# @return list of the vmware vsphere credentials
##
function retrieve_vsphere_credentials()
{
  var i, vmware_prefix, vmware_postfix, username, passwd, creds, result_array, kb_index,
    username_key, vmware_key, ignore_ssl;
  
  creds = make_list();

  # "VMware SOAP API Settings[password]:VMware password (unsafe!) :" 
  # KB entry like Secret/VMware/username
  vmware_key = "VMware";
  username_key = "login";

  for (i = 0; i < VMWARE_CREDENTIALS_LIMIT; i++)
  {
    # create prefixes
    if (i > 0)
    {
      vmware_prefix = "Additional ";
      vmware_postfix = " (" + i + ") : ";
      kb_index = "/" + (i - 1) + "/";
    }
    else
    {
      vmware_prefix = ""; # no prefix
      vmware_postfix = " : ";
      kb_index = "/";
    }

    var auth_method = script_get_preference(vmware_prefix + "ESX Authentication Method" + vmware_postfix);
    if (empty_or_null(auth_method))
    {
      auth_method = "Username";
    }

    username = retrieve_script_preference(pref:vmware_prefix + "VMware user name" + vmware_postfix);
    var pam_creds = _get_creds_from_pam(username:username, prefix:vmware_prefix, postfix:vmware_postfix, auth_method:auth_method);
    if ("Username" >!< auth_method)
    {
      username = pam_creds.username;
    }
    # check username is not null
    if (strlen(username) < 1)
    {
      if (COMMAND_LINE)
      {
        break;
      }
      if (i <= VMWARE_CREDENTIALS_LIMIT)
      {
        continue;
      }
      else
      {
        break;
      }
    }

    if ("Username" >< auth_method)
    {
      passwd = retrieve_script_preference(pref:vmware_prefix + "VMware password" + vmware_postfix);
      if (empty_or_null(passwd))
      {
        passwd = retrieve_script_preference(pref:vmware_prefix + "VMware SOAP API Settings[password]:VMware password (unsafe!)" + vmware_postfix);
      }
    }
    else
    {
      passwd = pam_creds.password;
    }
    
    # retrieve ignore ssl preference
    ignore_ssl = retrieve_script_preference(pref:"Ignore SSL Certificate : ");
    
    # store data in the creds list
    result_array = make_array("Secret/"+vmware_key+kb_index+username_key, username,
                              "Secret/"+vmware_key+kb_index+"password", passwd,
                              vmware_key+kb_index+"ignore_ssl", ignore_ssl,
                              vmware_key+kb_index+"auth_method", auth_method
    );
    
    creds[i] = result_array;
  }

  return creds;
}

##
# Wrap function for script_get_preference, so we can mask it with flatline
#
# @param [pref:String] preference name
#
# @return script_get_preference(pref)
##
function retrieve_script_preference(pref)
{
  return script_get_preference(pref);
}

## Used to gather credentials for vCenter API from PAM
#
# @param [prefix:String] preference prefix
# @param [postfix:String] preference postfix
# @param [auth_method:String] value from UI for PAM selection
# @param [username:string] some PAMs require username param
#
# @return [desc:array] result contains true/false and credentials
##
function _get_creds_from_pam(prefix, postfix, auth_method, username)
{
  var result, password;

  if ("Arcon" >< auth_method)
  {
    result = arcon::get_credential(username:username, prefix:prefix, postfix:postfix, type:"application");
    username = result.username;
    password = result.password;
  }

  if ("BeyondTrust" >< auth_method)
  {
    result = beyondtrust::get_password(login:username, prefix:prefix, postfix:postfix);
    password = result.body;
  }

  if ("CyberArk" >< auth_method)
  {
    if (retrieve_script_preference(pref:prefix+"CyberArk Host"+postfix))
    {
      password = cark_get_password(login:username, prefix:prefix, postfix:postfix);
    }
    else
    {
      result = cyberark::cyberark_rest_get_credential(username:username, prefix:prefix, postfix:postfix, vmware:true);
      username = result.username;
      password = result.password;
    }
  }

  if ("Delinea" >< auth_method)
  {
    result = delinea::rest_get_creds(prefix:prefix, postfix:postfix);
    username = result.secrets.username;
    password = result.secrets.password;
  }

  if ("Hashicorp" >< auth_method)
  {
    result = hashicorp::get_credential(username:username, prefix:prefix, postfix:postfix);
    username = result.username;
    password = result.password;
  }

  if ("QiAnXin" >< auth_method)
  {
    result = qianxin::get_credential(prefix:prefix, postfix:postfix, default_platform:"LINUX");
    username = result.creds.username;
    password = result.creds.password;
  }

  if ("Senhasegura" >< auth_method)
  {
    result = senhasegura::get_credential(prefix:prefix, postfix:postfix);
    username = result.creds.username;
    password = result.creds.password;
  }

  if ("Wallix" >< auth_method)
  {
    result = wallix::rest_get_credential(prefix:prefix, postfix:postfix);
    username = result.username;
    password = result.password;
  }

  if ("Fudo" >< auth_method)
  {
    result = fudo::get_credential(prefix:prefix, postfix:postfix);
    # Note that username is not retrieved from the integration.
    password = result.password;
  }

  return
  {
    username:username,
    password:password
  };
}
