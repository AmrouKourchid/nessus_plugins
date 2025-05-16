#TRUSTED 2afca8f7797c0ee29a1cd6db19c8cfbd139078e4ddb2f6cae50f3775c722147c321f126ca360a6882db6c3856741e798f9e05080b462c21553e9a93c1b563ce63fda61ebffc1cfcb3c1b48a2ab6fbf3b0098bc0f9fd1b78bcb595b7400d981450ed5adab6435a5a823b4a75e9669cfb2960187766d5985c7a1e4f9597675a38958a56bb0b432f2e82ba96f18cd5e29fa9023cec1d00eea2d7bc9233c940adac62b4185545efcec9e8424bfb67c92e5125bce151201c337ae25faa421079eb2e627a8f409abca9e9799294ebeb38f1d7d6dc84dec66531aee2f0218e45f9c3e81c9acff84b6db3eb468f5ec2ce9ed17b693ff691542ce01b8c4b491c80e37846132fe0d6ff197bd48c2a705fbde9e2c0b513c8d5c061c07f815e2bb40ee3ef6b69f573943eb5f8526cae23215221278a1eaeb8126b828740699297f8e48901946f12f4dbc7e796ad3664d3d315e5e32a0e5cedac378f72f67b5ac6ca7fe2b509f03b9f1743ebe63a0a54b96ff7a6289aed4e8bce1560b1173e1c7b05865b5af05c36bc6d700a5ec10af5dc4682e6fdf07a5ce3f72e4ff3474f7badc93912f9d250ae10462880e0f2411f62390ced6c97e7ea38a865eae2ce5138df070e036a49f84fd637087cda342702959b5eb59b3c13820b871b641a6dc572000f5024a33a40bd3dcffacc0ad7354441325404454919ba5e4fd151d2700525161026f74d1b0
#TRUST-RSA-SHA256 736a33096ec5fcaa81b27e5475c1e3e44362ab3b12e74ac1621767c13367daa242c793443401a40754d90fcb75329d253105d231e1a0262f63d4d49c635bb1a8de8cd8e150a46350d9dc6446a14740b0834abfb57ded29ce1d9cc20f0423e8044902ddd8eadf970609511a037806312f5d6b60879c826dea87b4c06b5f72a0c4c6991e6d2eee271b1e05b64cd5f6caa28c80c8e41a58caf5275e784609aa784f57aa86e18ea28c6afb948a5f322a97555838959e374d903dd1e2e50c06c177cfc12d2a2b4be4b3911af021d86113c55c2b226146563a99d5d1ef2fa60b21896e155c902deb487c38c4a29bea2a464a3a37b5e871f45573d4b520935ba974f51f8e496d4b799d4ada01254f5c6891463f17ea3790285d1890e061e81757cb3fcc349c3e1a5c24c1e20371996df26f3ce98f30e1f687f173ec247437d8cce3a992ea8d064548dfd3532a263eb0cc86287e1d4febf9f80a96808d12e659bdcc09438f2599c7b53adef970f79f1b2c45be8b73d3f895917d9f7ae37a60519477763fdc6ff677d33fbee55d955afa48fe68a0d24ce835c465902b29eb3bd2967b50dcd8575753e04e4718f5ae8ec66a6ff3b8458acd3ac7af662ad09e56dbcba5b1069a69e3ab3b3b983eed987733db86fe947412a57976426f94c4b9fe1f9098ef1a28bcf1724a8fabf8bd7e8c7084d8f450d3d97a28fc6d9199a85f726cfa755544
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# Revision: 1.9
#

include("compat_shared.inc");

##
# Gets the linux OS type.
#
# @return [string] Returns Debian or RedHat
##
function get_kb_linux_os_type()
{
  local_var release, oses, os;
  oses = ["Alibaba", "AlmaLinux", "AmazonLinux", "AzureLinux", "CBLMariner", "CentOS", "Debian", "EulerOS", "KylinOS",
           "McAfeeLinux", "OracleVM", "PhotonOS", "RedHat", "RockyLinux", "SuSE", "Ubuntu", "Virtuozzo", "ZTE-CGSL"];

  foreach os (oses)
  {
    release = get_kb_item("Host/" + os + "/release");
    if (!empty_or_null(release))
    {
        if(os == "Debian" || os == "Ubuntu") return "Debian";
        if(os == "SuSE") return "SuSE";
        return "RedHat";
    }
  }
  release = get_kb_item("Host/OS");
  if ('Solaris' >< release)
    return 'Solaris';

  return NULL;
}


##
# Get the kb rpm-list if there is one.
#
# @return [string] rpm-list or empty string if it does not exist.
##
function get_kb_rpm_list()
{
  var keys, rpm_list;

  rpm_list = get_kb_list("Host/*/rpm-list");
  keys = keys(rpm_list);
  if(!isnull(keys))
    rpm_list = rpm_list[keys[0]];

  if(!isnull(rpm_list))
    return rpm_list;

  return '';
}


##
# Get a list of packages from the KB.
#
# @param [name_pattern:string] Optional. Regex to filter results on the package name.
# @param [version_pattern:string] Optional. Regex to filter results on the package version.
#
# @return [array] Array of installed packages matching optional patterns.
##
function get_kb_packages(name_pattern, version_pattern)
{
  local_var os, arr;
  os = get_kb_linux_os_type();
  if(empty_or_null(os)) return NULL;

  if(os == "Debian") 
      arr = split(get_kb_item("Host/Debian/dpkg-l"), sep:'\n');
  else if(os == "Solaris")
      arr = split(get_kb_item("Host/nix/packages"), sep:'\n');        
  else
      arr = split(get_kb_rpm_list(), sep:'\n');
     
  # Return all packages if pattern arguments are null
  if(empty_or_null(name_pattern) && empty_or_null(version_pattern)) return arr;

  local_var packages = make_array();
  local_var pattern, match, key, item, version;

  # Match everything if no name pattern was provided
  if(empty_or_null(name_pattern)) 
      name_pattern = ".*";
  
  # Default version pattern will match numbers and letters
  if(empty_or_null(version_pattern)) 
      version_pattern = "[0-9a-zA-Z]+([\.-][0-9a-zA_Z]+){1,2}";
  
  if (os == "Debian") 
      pattern = "^ii\s+(" + name_pattern + ")\s+(" + version_pattern + ").*$";
  else if (os == "Solaris")
      pattern = "^(" + name_pattern + ")\s+(" + version_pattern + ").*$";    
  else if (os == "RedHat" || os == "SuSE") 
      pattern = "^(" + name_pattern + ")-(" + version_pattern + ").*$";
  
  key = 0;
  if (os == "Solaris")
    foreach item (arr)
    {
      match = pregmatch(pattern:pattern, string:item);
      if (!empty_or_null(match))
      {
        packages[key] = make_array();
        packages[key]['package'] = match[1];
        packages[key]['path_package'] = strcat('Package - ', pregmatch(string:match[0], pattern:name_pattern));
        packages[key]['name'] = match[1];
        packages[key]['display_version'] = match[2];
        packages[key]['version'] = pregmatch(string:match[0], pattern:version_pattern);
        key++;
      }
    }
    if (!empty_or_null(packages[key]['version'])) return packages;

  if (os != "Solaris");
    foreach item (arr)
    {
      match = pregmatch(pattern:pattern, string:item);
      if (!empty_or_null(match))
      {
        packages[key] = make_array();
        packages[key]['package'] = match[0];
        packages[key]['path_package'] = strcat('Package - ', path_package_output(str:match[0]));
        packages[key]['name'] = match[1];
        packages[key]['display_version'] = match[2];
        packages[key]['version'] = str_replace(string:match[2], find:"-", replace:".");
        key++;
      }
    }
    return packages;
}

function path_package_output(str)
{
  if('ii ' >< str)
    return debian_path_package_output(str:str);
  return redhat_path_package_output(str:str);
}

function debian_path_package_output(str)
{
  var list;
  list = split(ereg_replace(string:str, pattern:"\s+", replace:' '), sep: ' ', keep:FALSE);
  return strcat(list[1], ' ', list[2]);
}

function redhat_path_package_output(str)
{
  var list;
  list = split(str, sep:'|', keep:FALSE);
  return list[0];
}

##
# Determine Linux Distribution based on KB.
#
# @return [string] Linux distribution from KB.
##
function get_distro()
{
  var distro = NULL;

  var release_kb_list = get_kb_list('Host/*/release');
  if(empty_or_null(release_kb_list))
  {
    return NULL;
  }
  var release_kb_keys = keys(release_kb_list);
  var release_kb_name = release_kb_keys[0];
  var release = release_kb_list[release_kb_name];
  var release_parts = split(release_kb_name, sep:"/", keep:FALSE);
  distro = tolower(release_parts[1]);
  if (distro == 'redhat')
  {
    # Oracle stores it's release data in Host/RedHat/release but can be detected with the following KB item.
    if (get_kb_item('Host/OracleLinux'))
    {
      distro = "oraclelinux";
    }
    # Fedora stores it's release data in Host/RedHat/release but can be detected by looking for Fedora in the release string.
    else if ('fedora' >< tolower(release))
    {
      distro = 'fedora';
    }
  }

  return distro;
}
