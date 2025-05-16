#TRUSTED 92fb4b80df1e40e1a7b9445a0dec72c6535f446a1b783d6a3162ab1c9729a50b043ee7383bc175364a28ef3b832e2e3f32107e90cdee4387e0e07817618a6d5cdaeb2e1a320c23ae8477d08ccecdb25650ea294005b24ae6cdfe44a3055b7767983683a83aab36e7ec5dc52774b82cb64e7551762fa4a9e1ec204eed24a0dc827feef01f1b008269e3af316f5ba4c8a1aa26fd9d738e004c131a87f03ceac4749a410478bf29c9b895b646adad367b32bae4c60a5edb795d815d3e84bc2a48476b1a5e5508d04289dd2cbc50141ca0cae8ff08be6f86fa5f1bc1d2de3d757b3620b8b4566cd3bd97b4dcaafc0d7292b9f428ad273434af38b2c8626d2af1b09284e974b668fddce0504eecce86ec2435c5a1d046797d4256d0b01d3681d96b79899c0dc6ec58deaa804034d4b0bd56d81d804b9b3798917661597ad29c55556b326b69fc71e4f66ebc7490698a285d13a868e958c67ae8e67f2a030238c806123d657bbfa99c1300c64bc4ea6154addaca695bbda8006014f6bfcfaa66ec619d500f686ae9cfdfe6655bf33a9d4a4f8b06c7a747b4eb99c036af29f3a3d66d6fdf30fedb05e2566f65f7f927557b9d18672c8efb7500cced8551b48fe3940d8c76371f8a25941fdc5b23b35e08c603906c53f5ed5a4bcd04b8d8668e1d26053c861fc84a85cf0dd281fad48172336e85fdace8551e72394863776db93462cc70
#TRUST-RSA-SHA256 565319dd86514c04cf4096ec9532bec3913770642c9213cbde72c019e141153ec477558dca0ad116532108d6700c44d289b0923ba217e73830147ff9aef1390c5b3fd98dd16b9d2e18a5cfcec93c7cf8e015bd214cad910f50b06f2ab429e28825b22391c8a06205fe412b62086edff4d41021fca369adca1e795f6ee44afec53ddef6bf78afc33b8efca44c97280c3123afea38946e686d4e4b54737b345a993a756125bf222aed195ac83cc037705cd172e4a482dd9e9c240781bcce4c39bb4e929aa935a20e1a3a4059b193030ba1208f2ea84ddc5374d6f5dfc7f9fa084596a8b1f5bcd4b165a2f6c10c8ded5175a7847da0c4d46ad1997f365baedd14755f6b293bc6f23397c566d0488f45c6917edf6341f6361390b912b58690e9ae19af25eb98ba9b8219d005adfde3412effa5a4cb3f90d898a7a44a9939f72c0461404ddbf9ec3d5cbeae521983d6b67ad1f8dc615b3dfaa127c7cee9d1c9c91714398ab9b424c7d7730f9e7f8f635cf5f4a23d358a80df88b5d03cad3c45031f9ffaa3bc459e9bc590dc2b0ac0efd38346d58256b39472a462d56387c929f18056684f0fdfa04e5bfdc532cc09d5de7554e4acb0f5758771e5d7f22146438866e5b06c598be4228bcb6e489918642d8b4b35a6490fc761bc241a3ef67ea55eddc2c6d6d22dc0fa765f50c786462f9854664937d974375832f37e7651c567eb7fea

include("spad_log_func.inc");
include("debug.inc");
include("compat_shared.inc");
include("datetime.inc");

##
# Keeps track of the time a plugin has spent scanning the target.
# After the alloted time has passed, this function will always
# return FALSE
# 
# @param [time_expired:boolean] If the time we are alloted has already ended
# @param [pd:object] The prelim_data object the plugin is using
# @param [gathertime:integer] The total time alloted for gathering data. Should be less than the 
#        plugin's timeout
#
# @return [boolean] FALSE if time has expired or some other error, TRUE if we have time left.
##
function constrain_time(time_expired, pd, gathertime)
{
  if (empty_or_null(time_expired))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid time_expired arg.");
    return FALSE;
  }

  if (typeof_ex(pd) != "prelim_data")
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid pd arg.");
    return FALSE;
  }

  if (empty_or_null(gathertime))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Invalid gathertime arg.");
    return FALSE;
  }

  if (typeof(gathertime) != 'int')
    gathertime = int(gathertime);

  # This function may have already set the flag when called previously.
  if (time_expired) return FALSE;

  var difftime = datetime::timeofday_diff(begin:pd.data.start_time, end:gettimeofday());
  if (int(difftime) < gathertime)
  {
    return TRUE;
  }
  else
  {
    pd.append_data('time_limit_met', 1);
    return FALSE;
  }
}
