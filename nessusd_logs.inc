#TRUSTED 6080125a8398601b717f7a2d7c83821817020b21e0e385f42dc4e0ca9ae1face0d6a069993735256f122152ca8d74f5c33bf9eb668158cd8e248dab9956481571d63ccd4ca5d295fde0831466c2efe3799d41a2ed74f196cd91481bb4bdc017a5c3df106229f8e8d7536e4e4e3fbcacb12d2bf1bc5d6de516617309362e8f503969457547965efc83e16cf1ce065c7e68cbd1a7df6c1dbc500c0ae4edbed64e7bbcddc00813a43613b73c395ddb9f67a274a822184881942d01381ef2ad7f63ce1f4f2e73270df29b64661df4c9873b5a60bf663e1bae27acae7273b06ab76300bf45acd51e49b75470fa7b6d87d70dce429546aa659956a71142c109fe5ae6aabbc981ea022ca1440602ef368432fbe276b398c4a0a839c29ba7b2e7f654ae3675c562c40c1e599a63066a33ee7ffd396b9503dd891e642f832623384487f26d60fc868ea7b61ce23c28eeced498ecee8cfbf6d65c065680961f22e58b33893bdbf9fa15f33b7e2f0ec11116cf582f7a377d3a4cc5b71db4e48a489c0f1469c917ce24ef3783cbedc4090537049c973ac040d0046797e91fde946a21f86a525100958676936dcb7c7d8ebc386f2c083826a4416fba5f1ab13c05fb4917ba8f1ea8f71cfd4ab5b387c02f84485961ca4a18e462211d758cdab3234d5281bac43dbe0ad6691476acca60cb9df05968114a242f195afad8f57d2a09833dba17a06
#TRUST-RSA-SHA256 83bc3998bd35f1c2fb6b8ca7a30431bfabc50c188969c3faff44211ea1e5b7e65ef131e556399c0d6fd59f1ca7f0ff1e83d260c7a3f9c7f2093457d5695700e380cd85ee010cae85e820550c84c096350773a811c7964e96646d201b1ee218c15a4e5b8374c07e8209a11cd56d3cab013087fd3929e7eb6db0147c313366180742b7533ffe4fe175534cc3e47f7964bd102e524a549789eec59b72b333e963750e927c5794f5376cc9be6ab3544540e085d358f575194353bda38019dc421f41c67f5abfe17f7db9e136465a8754b4e9cdcec1cfc5b4b8e8c5c336b98443193eb861bb9e7a571b577fb020eaafc746f5a3ef9984f080ae06486f4bc9cc11b72a40f5ff5704e50d20c314fa6aadeb65576c8e0b541b4a6f488e44c21ec48e91e1f37d98f97a3df480c2fdabca98569537f8ba980c00f15816204d1139aeb9b5e3d54034f5327069e1d3b629b02a79adb5c0b9b592b26824e9784df8b84ee984990a0a549268fe8d50f7b9caee2fb6a1aa0e27423ab690ed6b65a74d56189777d4ae279a79f0bf7bf0a22418e787d91dce212f4b4f25fd4db475b022359468d6798711ea854ef37eb19a04469931ce98b323cb0d522c3ee8585f6ed7be23926209b76dfe949e7d12cb8b527fa1ac5fd9eb4125657efc9ab52a137918101ea5800f5cf848a420d3e2fde7602934f660f85423dfd929fbcdf339b63638d539e5dc59
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.3
#

#Matches the time portion of nessusd.dump and nessusd.messages log entries.
global_var NESSUSD_LOG_TIME_REGEX = "\[([MTWFS][a-z]{2} [JFMAJSOND][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})(?: [-+]\d{4})?\]";

#Match the threadId/processId and target for nessusd.messages log entries.
global_var NESSUSD_LOG_PRE_7_2_TID_PID_REGEX = "\[(\d+\.\d+)\].*finished in [0-9.]+ seconds for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})";
global_var NESSUSD_LOG_TID_PID_REGEX = "\[(\d+\.\d+)\]\[scan=[a-z0-9-]+\]\[target=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\].*: [fF]inished$";

#Matches the threadId/processId and plugin for nessusd.dump entries.
global_var NESSUSD_DUMP_LOG_REGEX = "\[(\d+\.\d+)\].*(?:\[plugin=| \()([-\w]*\.nasl|[-\w]*\.nbin)(?::0x[0-9a-f]*\)|\])";

global_var TAP_MODE;

##
# Determines whether the scanner version is less than 7.2.0
#
# @return TRUE if nessusd has a version less than 7.2.0
##
function is_nessusd_pre_7_2()
{
  var nessusd_version;
  if(TAP_MODE)
  {
    nessusd_version = _FCT_ANON_ARGS[0];
  }
  else
  {
    var env = nasl_environment();
    nessusd_version = env['version'];
  }

  if(!isnull(nessusd_version))
  {
    var ver_parts = split(nessusd_version, sep:'.', keep:FALSE);
    if(max_index(ver_parts) == 3)
    {
      if(ver_parts[0] < 7 ||
         (ver_parts[0] == 7 && ver_parts[1] < 2))  return TRUE;
    }
  }

  return FALSE;
}
