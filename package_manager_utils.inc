#TRUSTED 2fa7c61b1e64fa500d324e75f7db01f7d6ceb07088619e23d8901896292dfcfcf912730ec8cd12117fa7532c7062162b4ea7b5db5d93e1999c8a1c6f682af3bccbc89cda6066e293e7c4ed79bdccb9d6662268c3b685f9a86e99eb67737a650ed27543f03238c09eb30d7d75c070cf048c67321b8b6d3cf5f4aaf95f54d0d6fde1069bb5d3a2efe06fb06e9b919a9e2c93c116d21f0a89432560c3939288f6ec59a29ec6fb56dcfb60748f608bb73ec2273f8bf7ac4a1f1e16392c70e047514da4a85fc8932273abe78010fd12b02341f607d7e535854017e0436c435fe1d065586dc153702dd08831f2fb30953df53463b016f2eebd33e2c68e5f30633012ce4f73b94fdb2631749219d11f01ef332e9f1d9de420b9de7f964d49d74ec036c49b703026948aaa3f6c925667b9e6e3345723f441366845ab5e6d98f1ef3968e33accad59e560ba03fa5d6318cb34e30288a2549b5b76df632d43c5472c734ad95bcf772ece970143e06b14f918847ce37516cfeaf93f11128bbc0d474c4ce55d950db6539197dcb5810842514ece4ac2cdc746844ff1d9df9d5ab6c26a4b9f3c8e9657b6c63cecdf00bfc00ac39eea22503f1e4a1d9b7c69867cf842c946674a261c98765c11b571578297821e78a572af76747f2bf9f7400e89c9a356b5a8e30928488098b9caf6855c8b7adac8662d54b6ac864bd8fbebabb3bebb4bcf4b98
#TRUST-RSA-SHA256 388ed732e60b80248fe3c8d9210483bafe445865971696cad18dfe88504940e743e1cc7724abeab954a4994e49bc173a291daff32425a691d97127090f78ee92b3695b2afe704d7f1ffaf759664964c0f52adacc1aa64b9d9392d6b0f3fcd0f3e924110b8db15b4cdb23cbb8d8d6aef8bbf061826f5e22886caa4a347ad3754994fd7a61b9cf54bcfa093400a3efb0c3fb7f5fed0f3fadc57f064d2eb4ca36523bc20855ff9fc0618011bc61f0530fe63534d8fdec09f94083c448641df08a5b129861d9590364cee34a41ea45ebb766ea2b257cc8f203d976f38b36c0d0fc2c1a9020f0b618207bdd4c5ef1f453142115b62120cce74f8f5390706342230114dbc094f9b0df6e18aaff33a9c2c3d251ca228b7c754c2cfb0f2c8b333c817e5d439fd19f50cf6ca39621a73b2406fb1d5274ff5664167c417d98814a042a496905bd3ae5883813deca178ecc4cce05671a2b78ae7da10af04761c5bf051d640ebded3d52a095fb4780401254a971b281730b54391b0c74a9ccd10fdca7164152ca9c830f53be9ba21a9444119f74165181d432f9a7c172e3f5a6fa36c92b77106a2987609c477c9ae2d7a0f992df87570c078153fda1845240d39249f65937f0d3cb858df84ce8bde644eff60cc45f9c18c2ff2f5641ab357a9a28a1266153bca6d49bb7c9ce070677085f30d44feb6572f08490dc54b4ad1f80eb4078e7ce97

###
# (C) Tenable, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# @NOGPL@
#
# package_manager_utils.inc
#
# Revision: 1.1
#
###

include("compat_shared.inc");
include('debug.inc');
include("debian_package.inc");
include('rpm.inc');

namespace package_manager_utils
{
  
  ##
  # Generate normalized inventory packages list from KB data.
  #
  # @param [use_one_pkg_mgr:string] package manager kb string to bypass FA functionality
  #
  # @return [array] array respresenting normalized inventory packages list.
  ##
  function get_packages(use_one_pkg_mgr)
  {
    # Get the package listing
    #'Host/FreeBSD/pkg_info',
    #'Host/Gentoo/qpkg-list',
    #'Host/HP-UX/swlist',
    #'Host/MacOSX/packages',
    #'Host/Mandrake/rpm-list',
    #'Host/McAfeeLinux/rpm-list',
    #'Host/Slackware/packages',
    #'Host/Solaris/showrev',
    #'Host/Solaris11/pkg-list',
    #'Host/VMware/esxupdate',
    #'Host/VMware/esxcli_software_vibs',
    #'Host/XenServer/rpm-list',
    #'Host/Junos_Space/rpm-list'
    #'Host/AIX/lslpp'
    var pkg_mgrs = [
      'Host/Alibaba/rpm-list',
      'Host/AlmaLinux/rpm-list',
      'Host/AmazonLinux/rpm-list',
      'Host/AzureLinux/rpm-list',
      'Host/CBLMariner/rpm-list',
      'Host/CentOS/rpm-list',
      'Host/Debian/dpkg-l',
      'Host/EulerOS/rpm-list',
      'Host/KylinOS/rpm-list',
      'Host/McAfeeLinux/rpm-list',
      'Host/OracleVM/rpm-list',
      'Host/PhotonOS/rpm-list',
      'Host/RedHat/rpm-list',
      'Host/RockyLinux/rpm-list',
      'Host/Ubuntu/dpkg-l',
      'Host/Virtuozzo/rpm-list',
      'Host/ZTE-CGSL/rpm-list'
    ];

    if (!empty_or_null(object: use_one_pkg_mgr ))
      pkg_mgrs = [use_one_pkg_mgr];

    var type, package, res, item;
    var package_inventory = [];
    foreach var pkg_mgr (pkg_mgrs)
    {
      var packages = get_one_kb_item(pkg_mgr);
      if (!empty_or_null(packages))
      {
        pkg_mgr = ereg_replace(pattern:'^.*/.*/(.*)', replace:"\1", string:pkg_mgr);
        switch (pkg_mgr)
        {
          case 'rpm-list':
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Found RPM packages.");
            type = 'rpm';
            packages = fixup_rpm_list(packages);
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              res = parse_rpm_name(rpm:package);
              if (!empty_or_null(res['name']))
              {
                var epoch = '';
                if (!empty_or_null(res['epoch']) && res['epoch'] != '(none)')
                {
                  epoch = res['epoch'] + ':';
                }
                var release = '';
                if (!empty_or_null(res['release']))
                {
                  release = '-' + res['release'];
                }

                var version = epoch + res['version'] + release;
                item = make_array("type", type);
                item["properties"] = make_array("name", res['name'], 'version', version);
                append_element(var:package_inventory, value:item);
              }
            }
            break;
          case 'dpkg-l':
            dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:"Found DPKG packages.");
            type = 'dpkg';
            packages = _fixup_debian_dpkg_list(packages, keep_full_name:TRUE);
            foreach package (split(packages, sep:'\n', keep:FALSE))
            {
              # packages in `rc` status have been removed and should not appear in the inventory
              if (substr(package, 0, 1) == "rc") continue;

              res = NULL;
              res = _parse_debian_dpkg_name(dpkg:package, keep_full_name:TRUE);

              if (!isnull(res) && !empty_or_null(res['name']) && !empty_or_null(res['version']))
              {
                item = make_array("type", type);
                item["properties"] = make_array("name", res['name'], 'version', res['version'], 'metaname', res['metapackage']);
                append_element(var:package_inventory, value:item);
              }
            }
            break;
          default:
              continue;
        }
      }
    }
    
    return package_inventory;
  }

  ##
  # Get package data from target.
  #
  # @param [get_source_mapping:bool] enable gathering source mapping data
  #
  # @return [array|NULL] NULL if a support package type isn't found.
  #                      An array of the follow structure if a supported package type is found.
  #                      {
  #                        type: Package type
  #                        packages: Installed package data
  #                        source_mapping: Source to child package mapping data
  #                      }
  ##
  function get_package_data(get_source_mapping)
  {
    var package_source_mapping;

    var package_types = [
      {"type": "rpm", "kb_key_pattern": "Host/*/rpm-list"},
      {"type": "dpkg", "kb_key_pattern": "Host/*/dpkg-l"}
    ];

    foreach var package_type (package_types)
    {
      var package_data_kb = get_kb_list(package_type["kb_key_pattern"]);
      if (!empty_or_null(package_data_kb))
      {
        var package_keys = keys(package_data_kb);
        var package_key = package_keys[0];
        var packages = get_packages(use_one_pkg_mgr: package_key);
        if (get_source_mapping)
        {
          package_source_mapping = get_source_packages_by_packages(pm_type:package_type["type"]);
          return {type: package_type["type"], packages: packages, source_mapping:package_source_mapping};
        }
        
        return {type: package_type["type"], packages: packages};
      }
    }

    return NULL;
  }

  ##
  # Gather the package data associated with a source package. This call will
  # find the package based on the source package name. If you need to find what
  # packages are associated with a source package then use get_source_packages_by_packages()
  #
  # @remark the content of this function is set in set_source_package_mapping.nasl
  #
  # @param [pm_type:string] which package manager data do you want to source from (dpkg or rpm)
  # @param [source_package:string] name of the source package you want to get the package data for 
  # @remark if source_package is NULL it will build a table of kb items with lists of associated packages 
  #
  # @return [NULL] on error, [array] format {kb_key:[package,package]}
  ##
  function get_packages_by_source_packages(pm_type, source_package)
  {
    if (pm_type !~ "rpm|dpkg") return NULL;
    # check if the package manager source data was gathered by set_source_package_mapping.nasl
    if (isnull(get_one_kb_item("srcpackage/set/"+pm_type))) return NULL;
    
    # if no source_package is provided then return all source_package
    if (isnull(source_package)) source_package = "*";

    var srcpackage_kb_item = strcat("srcpackage/",pm_type,"/source/",source_package);
    var pkg_src = get_kb_table(srcpackage_kb_item);
    dbg::detailed_log(lvl:4, msg:strcat('===',srcpackage_kb_item,'===\n', serialize(pkg_src)));

    return pkg_src;
  }

  ##
  # Gather the source package data associated with a package. This call will
  # find the source package based on the package name. If you need to find what
  # package is associated with a source package then use get_packages_by_source_packages()
  #
  # @remark the content of this function is set in set_source_package_mapping.nasl
  #
  # @param [pm_type:string] which package manager data do you want to source from (dpkg or rpm)
  # @param [package_name:string] name of the package you want to get the source package data for 
  # @remark if package_name is NULL it will return a key value pair of all packages
  #
  # @return [NULL] on error, [array] format {package_name:source_package}
  ##
  function get_source_packages_by_packages(pm_type, package_name)
  {
    # we only support rpm and dpkg at this time
    if (pm_type !~ "rpm|dpkg") return NULL;
    # check if the package manager source data was gathered by set_source_package_mapping.nasl
    if (isnull(get_one_kb_item("srcpackage/set/"+pm_type))) return NULL;

    # if no package is provided then return all using the serialized output stored
    # in set_source_package_mapping.nasl
    if (isnull(package_name))
    {
      var package_source_mapping = get_one_kb_item("srcpackage/" + pm_type + "/package_source_mapping");
      if (isnull(package_source_mapping)) return NULL; # this should never happen

      dbg::detailed_log(lvl:4, msg:"Returning package_source_mapping.");
      return deserialize(package_source_mapping);
    }

    var srcpackage_kb_item = strcat("srcpackage/",pm_type,"/Package/",package_name);
    var pkg_src = get_one_kb_item(srcpackage_kb_item);
    dbg::detailed_log(lvl:3, msg:strcat(srcpackage_kb_item, "=", pkg_src));
    if (isnull(pkg_src)) return {}; # return an empty array when there are no matches

    # this format is needed because nasl arrays cannot use variables to set the key
    var ret = {}; 
    ret[package_name] = pkg_src;
    return ret;
  }
}

