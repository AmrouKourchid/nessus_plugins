#TRUSTED aecbd91aa06d211f3d2e048a8428dd9122271a11a95c7b43265c7ad42fdf8e31924794e28fd073f2d141f23525c55a7204815feafc8b75171ddb0ddf1ee680cc45a6d355108e20f4b3608b41daad559d443830bff532ec9ead6fd160ad5b81728ba893dfb8327124b0c2d8a1ba641381e0d194a1ee78af2e99d81bc522ece35eddf6c4b69f04f5bcfd1ae44450cd35afe6a6449c6fdc89b15fb5514cdd7ede469f4c8352b4ed49ddd59fa1173577cd75890e773d913d84cb478f205e856d0605ad907b03286e5820dac2022f4576c03080325e72acd625392026155ac0bc60224a850d9de0d93cddd6af917231b9d5e5a2c8a4b35d06f0d24b1161f5c44cebd662f0a8e19f02ae12090f8a66df9a5c89249af2bfc5a1651b5f62b78ad125ef76ab6fb4fe7d4dca3901239c1e0bcfa1c35ac9628bf833b39eb8e81fbef5a6817093a037c7014a7c273f5b46d448424c4fe40bc845a84272fcecc7cc55650083a507ff2ef8e43e19f68a924268ca05408332f8da81be4f96a446012dede8c6062f19b3066c7e9409ced59d0ea28e6283386894d2c1fd91546f93f1fb6d650bce45eea49764b318bf22f396ed486c8cdf50f12a77a99cb45bcc642e66f96d4bc1688a5d2666a3917344680f706c8a20023e070f8fcf490c07a84ac81b0f361c283c49a16ee3961b81734b992e959bc6dc8af46c60909deaaa1b852e1759999a48e8
#TRUST-RSA-SHA256 26ce618fa428fe0897f9db83d73cd7c928e98b560f8f3dee82802d538290fce05e945930aa985684eb72bf0d76270aee17013f045b57d3417f0a1c95112fd75bf8f09b51f406398fa8ee53c1f51817b34063977a76f7fa28eed7449f5674d3e1710049270ec8d7183347794ba206d94d3af59bb3c33f297e2edfae7b0e18e26b4fcf861c469cf51a2637695691648958ad076d1a72690a21d2ce7d053f4f36fc121a94a2eb12f388a7806b1a65da687a777f810379a6d27b66d360031b9f49ccc376e13c8c2e34439df6dfc2012ccb6c7a4459292f213ce136cdca2a351c6a8c37321e06b7007a8975713cffed6340631218a15137316981db66332be13ef06b35974aab21e267dd69f6d01a2b3f4958acf3fe16bb8590f6b6d4dee512ee9318ef315c131390318efa47c8acfb6d762babe71857dc51d89a155d8e8f67656dd06bd371e41f0d0d2e7e9a324be521e5430c0d69c837ef53c66cce33882f50df4d4222f914c230b8a6e566063c685d5a3580481ebd0ace520346d5516883882305a7a783fbef7c5245952fc1a54c8651732576fce3d54786d3514a103822930884fed82a00a9e9f448894872277289b89e420c4d7b3df9cbeb666feb47f7e74f1a1c25585ec6d7788e66a1290e079c366b019e86e0c079c748cbdaa482acee46055cef1df7a2ee570298c8b2ea01753cb24b483e6a7ea3cc060338aa8a0de9bf17
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234444);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_name(english:"Gather Source Package Manager Packages (nix)");

  script_set_attribute(attribute:"synopsis", value:"Gather the source package data to be used by future plugins.");
  script_set_attribute(attribute:"description", value:
"Gather and store the source package data for rpm and dpkg package managers
for future use during the scan.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");


  script_dependencies("unix_enum_sw.nasl");
  script_require_ports("Host/uname");

  exit(0);
}
include("debug.inc");
include("ssh_func.inc");

namespace set_source_packages
{

  ##
  # Setup the connections and requirements for this plugin to run
  #
  # @return [array], contains ssh_sock if not localhost
  #
  # @remark this function exits if requirements are not met
  ##
  function init()
  {
    var return_settings = {};

    get_kb_item_or_exit('Host/local_checks_enabled');
    var uname_kb = get_kb_item_or_exit("Host/uname");
    if ("Linux" >!< uname_kb)
    {
      audit(AUDIT_OS_NOT, "Linux");
    }
  
    enable_ssh_wrappers();
  
    if (islocalhost())
    {
      if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
      info_t = INFO_LOCAL;
    }
    else
    {
      sock_g = ssh_open_connection();
      if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
      info_t = INFO_SSH;
      return_settings["ssh_sock"] = sock_g;
    }

    return return_settings;
  }

  ##
  # Get source RPM packages and associated child packages from the target.
  #
  # @return [array] Array of package names and their associated source package.
  ##
  function set_rpm_source_packages() {
    var package_source_mapping = {};
    var rpm_buf = info_send_cmd(cmd:"/bin/rpm -qa --qf '%{NAME},%{SOURCERPM}\n'");
    dbg::detailed_log(lvl:4, msg:rpm_buf);
    var lines = split(rpm_buf, keep:FALSE);
    foreach var line ( lines )
    {
      # Validate line matches expected package to source rpm mapping format.
      if(line =~ '^.+?,.+?\\-.+?\\-.+?\\.src\\.rpm$')
      {
        var entry = split(line, sep:',', keep:FALSE);
        var pkg_name = entry[0];
        var src_rpm = entry[1];

        # RPM src packages have the format NAME-VERSION-RELEASE.src.rpm
        # The NAME can also contain '-' characters.
        # The follow code strips off the -VERSION-RELEASE.src.rpm portion of the source rpm.
        var src_pkg_parts = split(src_rpm, sep:'-', keep:FALSE);
        var src_pkg = src_pkg_parts[0];
        # Build the NAME up leaving off -VERSION-RELEASE.src.rpm
        for(var i = 1; i < max_index(src_pkg_parts)-2; i++)
        {
          src_pkg += '-' + src_pkg_parts[i];
        }
        set_kb_item(name:"srcpackage/rpm/Package/"+pkg_name, value:src_pkg);
        set_kb_item(name:"srcpackage/rpm/source/"+src_pkg, value:pkg_name);
        package_source_mapping[pkg_name] = src_pkg; # used for easy access to the entire mapping later
      }
    }

    if (!isnull(get_one_kb_item("srcpackage/rpm/Package/*")))
    {
      set_kb_item(name:"srcpackage/set/rpm", value:true);
      set_kb_item(name:"srcpackage/rpm/package_source_mapping", value:serialize(package_source_mapping));
      return true;
    }
    return false;
  }

  ##
  # Get source DPKG packages and associated child packages from the target.
  #
  # @return [array] Array of package names and their associated source package.
  ##
  function set_dpkg_source_packages() {
    var package_source_mapping = {};
    var dpkg_buf = info_send_cmd(cmd:"dpkg-query -W -f '${Package},${source:Package}\n'");
    dbg::detailed_log(lvl:4, msg:dpkg_buf);
    var lines = split(dpkg_buf, keep:FALSE);
    foreach var line ( lines )
    {
      # Format PACKAGE_NAME,SOURCE_PACKAGE_NAME
      # Names are valid Linux file names and cannot contain '/'
      var match = pregmatch(pattern:'^([^/]+),([^/]+)$', string:line);
      if(!isnull(match))
      {
        set_kb_item(name:"srcpackage/dpkg/Package/"+match[1], value:match[2]);
        set_kb_item(name:"srcpackage/dpkg/source/"+match[2], value:match[1]);
        package_source_mapping[match[1]] = match[2]; # used for easy access to the entire mapping later
      }
    }

    if (!isnull(get_one_kb_item("srcpackage/dpkg/Package/*")))
    {
      set_kb_item(name:"srcpackage/set/dpkg", value:true);
      set_kb_item(name:"srcpackage/dpkg/package_source_mapping", value:serialize(package_source_mapping));
      return true;
    }
    return false;
  }

  function close()
  {
    if (info_t == INFO_SSH) ssh_close_connection();
  }

}

set_source_packages::init();
set_source_packages::set_dpkg_source_packages();
set_source_packages::set_rpm_source_packages();
set_source_packages::close();

