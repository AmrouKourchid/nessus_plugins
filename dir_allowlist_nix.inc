#TRUSTED 4a9d0bf87b9fbeef97c288a5b631369396cf59c132291f7c0d0f73a24305bdd8f98dfc17dc11dd1e5d0b6a8d1153018e3555df0be254eebe3abe4694f3c4e5c46d0f524a92b2b3293b2cc2e52e61dab3c33971188f21b90fe10560b4e969bba37b7a3dc313d2b0a9096ddb38e45ce6a915c4021a0c4f9253aea93bc2efca9807818364619ccd0642664179ecff493fc3027c6dd814e3a14184c61ef8369c627995ae6c16a8da8cc89aa43dd8ac60c96ea87c0e45dbe14f33ae3b5af3ef2a044a5d9329f8e6b9082651273abf8accd42bbfbfd366074d6b02d299ce14a15657f0d6060235f43989df6b39fa584fd3bc0d66430834732e1ce73407744afdba0c3dfae9a1f870976b48df11118131ff66882002c75722073175878c5a82aaae4b7a270a2d70f6f3e5a83c3543c90a3f8bb2583f5da4113b474bba2123a7b2d255c3afa4b204e8543aa4c5217fd1599ee214e58a306869fe970f2b6e437206bb79acb528df42ebd9e0040ee69c176c1d40ad909b003d7dc75990b817252e403183c79ac6cf32a14152a50f99555f3b1761ec729ada8974541ae7eb17779775979c1fbdb28de9382e2c33b3ba2f0507b834793bc5f7b7b307217ef352cd70b758561dfb5f9cb2b283d75c63f03d647e1882f748b9421f6c74289ebae375c4a680aa736ceeb7160a95c84f44a0f679fbca87a8878bab5d25e00d8c0376fe04a8d71522
#TRUST-RSA-SHA256 7a1b5e92343702322e8c9d247a2939527b5682717278161589531beb3dc56e26365688fd39ca8de24a5346b4866956fa346200b06f28fd273ee4a1704385e2f7c0beab4b676dcff170439c41b842f30687dbcd5ebeef88c538ab91860a067d1fa30aa213d444d1a0368379996108333fdfe4f5a6886508c8a89d912db994c0cb41c3daa92c25f51b0651c3c2e524ff78c5ed505e07238062fa6d1cc4f6a346b8f99cc05fb8e78abd85362f80f48d24c19ad0160b837b55e94cb7bdbcf61909cc1bc7870bd7296149eddf4b330e404d7a18637aaa350dd328d72c0cf0b355e0cfb6c157be636fbd80bc9283456da1e06449263794e9c55196c194bc6637f4a9c180d9d9c7e6512475701729d0922c5732974348ce01772e871007eedf357c250f65231bf2d14fef71ecbb45412c8ce62516579bd14771de45cb45e71a794bfbd47542e6eaa105da7e8bbd274b9f5f47032ec4a2630012ba1723dd605880179815cb51366e798cbd0c678d5e8c4d408af09d9312ff4f217f308bd4d61ebb6be2c6dbe9dcff935936c4f37915d467a0dab1b5812153b06e8e4952b4c31d69750b2bae76050209e72f3bafbb0828dec089cff2afc024452bd1d97738dd959f4ffa795fc208804e7086e179818d2cf944a2f597dd1299920a8bc92daf3722f2cff9a3e4faf33c298669636e7996e3047a62bc843431eda57910b6b320d3629e37eb52

include("compat_shared.inc");
include('debug.inc');

##
#
# @param path : path to check
# @param nix_allowlist : allowlist to use (can be a custom-supplied list)
# @return TRUE/FALSE
## 

function nix_path_allowed_via_allowlist(path, nix_allowlist)
{
  if (empty_or_null(path))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'no path provided');
    return FALSE;
  }

  if (empty_or_null(nix_allowlist))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'no allowlist specified');
    return FALSE;
  }
  else if (typeof_ex(nix_allowlist) != "list")
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'bad allowlist format (should be list)');
    return FALSE;
  }
  

  var dir_allowed = FALSE;
  foreach var allow_dir (nix_allowlist)
  {
    var allow_pat = "^" + allow_dir;
    if (path =~ allow_pat)
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'path ' + path + ' matched in allowlist');
      dir_allowed = TRUE;
    }
  }

  return dir_allowed;
}



##
#  Application-specific allowlists begin here
#
#  Protip: try to reuse allowlists if possible
##


##
#
# The following is used by
# nbin/detection_scripts/java_jre_installed_unix.nasl
#
##
var java_allow_dirs = [
  '/apps'              ,
  '/data/docker'       ,
  '/opt/app'           ,
  '/opt/appdynamics'   ,
  '/opt/apps'          ,
  '/opt/arcsight'      ,
  '/opt/atlassian'     ,
  '/opt/axway'         ,
  '/opt/CA'            ,
  '/opt/data'          ,
  '/opt/docker'        ,
  '/opt/egurkha'       ,
  '/opt/grid'          ,
  '/opt/ibm'           ,
  '/opt/IBM'           ,
  '/opt/java'          ,
  '/opt/jitterbit'     ,
  '/opt/measurement'   ,
  '/opt/nimsoft'       ,
  '/opt/nomad'         ,
  '/opt/oem'           ,
  '/opt/oracle'        ,
  '/opt/oracle.ahf'    ,
  '/opt/Oracle'        ,
  '/opt/patrol'        ,
  '/opt/riverbed'      ,
  '/opt/SAPClient'     ,
  '/opt/SAPClients'    ,
  '/opt/splunk'        ,  
  '/opt/SumoCollector' ,
  '/opt/tibco'         ,
  '/opt/vmware-jre'    ,
  '/ora/orasoft'       ,
  '/pkgs/JDK'          ,
  '/srv/prop'          ,
  '/tupl/docker'       ,
  '/u01/'              ,
  '/u02/'              ,
  '/u03/'              ,
  '/u04/'              ,
  '/usr/apps'          ,
  '/usr/bin'           ,
  '/usr/java'          ,
  '/usr/jdk'           ,
  '/usr/lib'           ,
  '/usr/local'         ,
  '/usr/openv'         ,
  '/usr/sap'           ,
  '/usr/share'         ,
  '/var/lib'           ,
  '/var/vcap'
];

