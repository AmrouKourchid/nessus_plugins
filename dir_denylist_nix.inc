#TRUSTED 3b59784428296ede877a21ac773ca3fc8f4094ec76e1ad2d7c2e0234d1fc2b4bce3faf5865cfc583af1ea19dd33339a6863f8d4c86f823773f9e6bdd5a694076d7c5b46c5808150d659afff68803a4df7e8e45d15b1062be15098d424b1479c29a8b3b6d65f10c8655fa2e6441d2fdde0e5723cf5d7f1d7723a52f16c1f24b5fcab6d23df72414b5125478db2114e6c213067aaddc125fdecc0df4f0b47062f7615b106e15be1440ddc96b40953879393c6943c5ee301c64ec7921e8648b6a8dac7ddd20b53cc19de95483218e11c5eec952cbb98bc95d70a87914c8a4338a25abe7a1f53970fd26712f051affbb4b457a5c7b26f69f5dc164f301e91efeb1df4df3b8cbd607a3fc17b95667a00e31521122c27183365147f008b7dee5f49ef035ebd300adc68971de98cb0fcaf5717d9bbef4edf5998fbfa4fe10f1cdbea836f453fdf8d756802924ceaec552cb26f3e439a583b5c955dfc27968d606d297028340bf1734ce324dde0b5a4c5933fea69d61ada69f4f57c9e41357a403c538f1a58cf9901419954cce3bc344c124fe77f5f3ed5846d06c852bac7529d7699d59c959be0f6cbb11901e0fa07c0a64adc228c5aed92175766824155f4813482993468dcddc73e9cd80de2f630ee36aa821c2e437c6a98fda715fc90e5d448b2c0f335b4f8068ef87969546e9f05b9de18fa740306487e2857ba0f1f801b1c01989
#TRUST-RSA-SHA256 2246e98a4c1d0372f085ead1536859262e87aee429c05a440b8898c858c9757fc42bf3db5abf583a3bdad1e7371ef7bd3cc0b5de038fb7b392766b82ae91fec6aa4ac64acf51dbb8b0b5fb32cab8c352c0b4db567206cd128f7107c18a9788acf22622c2063ee2b6b50275ec4a653250d988c20c9bc98bef787b45f275bd341c3f436c95b7823127d8a6bd2343e58bd3cf991b11f682ef59d02444e117440ba2913a1de21a4992f51da2579bb842f78639b30a1810a69784af55a44125dc28a9ca00de0f491e0d2e34a43bcce901a8423c23ae4de661232018072ac97cc12df4caf8b8f3bdbdbe7180dedd7a48bce85d4db608bedbb8ee2db6f383666c6ad2affa43f1687c87dcdf56a4e853bda23442d2dbc0fccf84a8716de7724ac91d49dcb86c41f01c8d93a3d20fcfecdd7d4f5cdd9bd7e080e0474114902d1f7ea7fc719e8c332aaac64503f923cb16fda95c3d88d628003aa61b608be735ac353775e5df5779f36fc5f65bc1509aa931d5df0433717420f88169ff3349747e34289d64b7495597a9ab3578be527544f6672193673db128718c929a02ea2d711c4f8e63706cd2fd948f9f52888ac43b80c3fab1e6c09bbbdce6564b8fb3b13f463e46d930da7c833e2d979f4c59de60dcaf9c52f9fdbdf410c57cd755d35daa41ad9ffed987c81ecd5f80e0d432c8732cbe18476b0d013fee6f138e96ccc284b9421c9e

include("compat_shared.inc");
include('debug.inc');

##
#
# @param path : path to check
# @param nix_denylist : denylist to use
# @return TRUE/FALSE
## 

function nix_path_excluded_via_denylist(path, nix_denylist)
{
  var logging;
  if (empty_or_null(path))
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'no path provided');
    return FALSE;
  }

  if (!empty_or_null(nix_denylist))
  {
    logging = 'Denylist specified: ' + obj_rep(nix_denylist);
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:logging);
  }

  if (typeof_ex(nix_denylist) != "list")
  {
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'bad denylist format (should be list)');
    return FALSE;
  }

  var dir_allowed = TRUE;
  foreach var deny_dir (nix_denylist)
  {
    var deny_pat = "^" + deny_dir;
    if (path =~ deny_pat)
    {
      logging = 'Path ' + path + ' matched in denylist'; 
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:logging);
      dir_allowed = FALSE;
    }
  }

  return dir_allowed;
}



##
#  Application-specific denylists begin here
#
#  Protip: try to reuse denylists if possible
##


##
# The following seems like a sensible starting point
#
# nbin/detection_scripts/zoom_nix_installed.nasl
##
var default_deny_dirs = [
  '/home'             ,
  '/tmp'              ,
  '/Users'            ,
  '/var/tmp'
];

