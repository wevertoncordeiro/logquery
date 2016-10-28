<? include 'common.php'; ?>
<?
  $_SESSION['refresh'] = true;
  $_SESSION['type'] = "dns";
  $my_delta = $_SESSION['type'].'_my_delta';
  $my_index = $_SESSION['type'].'_my_index';
  $id = -1;
  $last_query = "";
  $window = (isset($_GET['window']) || isset($_POST['window']));
  if ($_SERVER['REQUEST_METHOD'] == "GET") {
    if (isset($_GET['client'])) {
      $id = $_GET['client'];
      $tag = '/RESULT/ENTRY/CLIENT';
    } else if (isset($_GET['my_q'])) {
      $last_query = trim($_GET['my_q']);
      $id = trim($_GET['my_q']);
      $tag = '/RESULT/ENTRY/QUERY';
    }
  }
  $i = 0;
  $count = 0;
  if ($_SERVER['REQUEST_METHOD'] == "POST") {
    if (isset($_POST['my_index']) && $_POST['my_index'] >= 0) {
      $_SESSION[$my_index] = $_POST['my_index'];
    } else
      $_SESSION[$my_index] = 0;
    if (isset($_POST['my_delta'])) {
      if (is_numeric($_POST['my_delta']) && $_POST['my_delta'] > 0)
        $_SESSION[$my_delta] = $_POST['my_delta'];
      else
        $_SESSION[$my_delta] = 0;
    }
    if (isset($_POST['begin']))
      $_SESSION[$my_index] = 0;
  }
  $begin = $_SESSION[$my_index];
?>
<html>

<head>
  <title><? echo ":: ".$program_name." - DNS Query"; ?></title>
  <link href="css.css" type="text/css" rel="stylesheet" />
  <link href="style.css" type="text/css" rel="stylesheet" />
  <script language="javascript" src="common.js"></script>
</head>

<!-- query begin -->
<!--
<? echo $_SESSION['query']; ?>
-->
<!-- query end -->

<body bgcolor=#FFFFFF>

<table width="100%" border="0" cellpadding="2" cellspacing="0" class="control">
  <tr class="header">
    <td height="25" class="header">
      <b>&nbsp;Result - DNS&nbsp;&nbsp;&nbsp;</b>
      <a href="dns.php<? if ($window) echo "?window=1"; ?>" class="menuitem" alt="Reload Table" hspace="2"><img src="reload.gif" border="0"></a>
    </td>
  </tr>
  <tr>
    <td>
      <table border="0" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="10%" class="aba" nowrap="nowrap" align="left">
<?
  if (!$window) {
?>
            <form action="index.php" method="POST">
              <input type="submit" class="button" value=" Back to Query " style="width:100px">
            </form>
<?
  } else {
?>
            &nbsp;
<?
  }
?>
          </td>
          </td>
          <td width="10%" class="aba" nowrap="nowrap" align="left">
            &nbsp;
          </td>
          <form action="dns.php" method="POST">
          <td width="10%" class="aba" nowrap="nowrap" align="left">
            Results per page:
          </td>
          <td width="20%" class="aba" nowrap="nowrap" align="left">
            <input type="text" name="my_delta" class="fixed" value="<? if (isset($_SESSION[$my_delta])) echo $_SESSION[$my_delta]; else echo "60"; ?>">
          </td>
          <td width="20%" class="aba" nowrap="nowrap" align="left">
<?
  if ($window) {
?>
            <input type="hidden" name="window" value="1">
<?
  }
?>
            <input type="submit" class="button" value=" OK " style="width:100px">
          </td>
          </form>
          <td class="aba" nowrap="nowrap" align="left">
            &nbsp;
          </td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td>
      <div align="center"><center>
        <table width="100%" border="0" cellpadding="1" cellspacing="0" class="lista">
          <tr class="item">
            <th align="left" class="item" width=10%>Date</th>
            <th align="left" width=10%>Time</th>
            <th align="left" width=30%>Client</th>
            <th align="left" width=5%>Query</th>
            <th align="left" width=45%>
              <form action="dns.php" method="GET">
<?
  if ($window) {
?>
                <input type="hidden" name="window" value="1">
<?
  }
?>
                <input type="hidden" name="my_index" value="<? echo $_SESSION[$my_index]; ?>">
                <input class="fixed" type="text" name="my_q" style="width:150px" value="<? echo $last_query; ?>">&nbsp;
                <input type="submit" class="button" value=" Filter ">
              </form>
            </th>
          </tr>
<?
  /* main prog */
  $different_ips = 0;
  $config = $_SESSION[$_SESSION['type']];
  if (isset($config['/RESULT/TYPE'][0]) && $config['/RESULT/TYPE'][0] == "dns") {
    if (isset($config['/RESULT/ENTRY/DATE']))
      $count = count($config['/RESULT/ENTRY/DATE']);
    else
      $count = 0;
    if (isset($_SESSION[$my_delta]) && $_SESSION[$my_delta] == 0)
      $_SESSION[$my_delta] = $count;
    if ($count > 0) {
      if ($id == -1) {
        for ($i = $_SESSION[$my_index]; $i < $_SESSION[$my_index] + $_SESSION[$my_delta] && $i < $count; $i++) {
          if (!isset($ips[$config['/RESULT/ENTRY/CLIENT'][$i]])) {
            $different_ips++;
            $ips[$config['/RESULT/ENTRY/CLIENT'][$i]] = 1;
          }
?>
          <tr class="text" onclick="return changeColor(this);">
            <td><? echo $config['/RESULT/ENTRY/DATE'][$i]; ?></td>
            <td><? echo $config['/RESULT/ENTRY/TIME'][$i]; ?></td>
            <td><a href="dns.php?client=<? echo $i; if ($window) echo "&window=1"; ?>"><img src="search.gif" border="0"></a>
              <? if (!$window) { ?><a href="javascript:open_win('process.php','firewall_src=<? echo $i; ?>');"><? } ?><? echo $config['/RESULT/ENTRY/CLIENT'][$i]; ?><? if (!$window) { ?></a><? } echo "\n"; ?>
            </td>
            <td colspan=2><? echo $config['/RESULT/ENTRY/QUERY'][$i]; ?></td>
          </tr>
<?
        }
      } else {
        for ($i = $_SESSION[$my_index]; $i < $_SESSION[$my_index] + $_SESSION[$my_delta] && $i < $count; $i++) {
          if ($tag == "/RESULT/ENTRY/QUERY") {
            if ($id != "" && !stristr($config[$tag][$i], $id))
              continue;
          } else if ($config[$tag][$i] != $config[$tag][$id])
            continue;
          if (!isset($ips[$config['/RESULT/ENTRY/CLIENT'][$i]])) {
            $different_ips++;
            $ips[$config['/RESULT/ENTRY/CLIENT'][$i]] = 1;
          }
?>
          <tr class="text" onclick="return changeColor(this);">
            <td><? echo $config['/RESULT/ENTRY/DATE'][$i]; ?></td>
            <td><? echo $config['/RESULT/ENTRY/TIME'][$i]; ?></td>
            <td><a href="dns.php?client=<? echo $i; if ($window) echo "&window=1"; ?>"><img src="search.gif" border="0"></a>
              <? if (!$window) { ?><a href="javascript:open_win('process.php','firewall_src=<? echo $i; ?>');"><? } ?><? echo $config['/RESULT/ENTRY/CLIENT'][$i]; ?><? if (!$window) { ?></a><? } ?>
            </td>
            <td colspan=2><? echo $config['/RESULT/ENTRY/QUERY'][$i]; ?></td>
          </tr>
<?
        }
      }
    } else {
?>
          <tr class="text">
            <td colspan="5" align="left" class="text" colspan=7><center><b>No results</b></center></td>
          </tr>
<?
    }
  } else if (isset($config['/RESULT/TYPE'][0]) && $config['/RESULT/TYPE'][0] == "error") {
?>
          <tr class="text">
            <td colspan="5" align="center" class="text" colspan=7><center><b>Error <? echo $config['/RESULT/ENTRY/ERROR'][0]." : ".$config['/RESULT/ENTRY/MESSAGE'][0]; ?></b></center></td>
          </tr>
<?
  } else {
?>
          <tr class="text">
            <td colspan="5" align="left" class="text" colspan=7><center><b><? print_r($config); ?></b></center></td>
          </tr>
<?
  }
?>
          <tr class="item">
            <td colspan="8">
              <table border="0" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <th width="10%" align="left" class="item">Total Entries:</th>
                  <th width="10%" align="left"><? echo $count; ?></th>
                  <th width="20%" align="left" class="item"><? if ($count > 0) { echo "Showing from ".($begin + 1)." to ".$i; } else echo "&nbsp;"; ?></th>
<?
  if ($count > 0) {
    if ($_SESSION[$my_index] > 0) {
?>
                  <td width="20%" class="aba" nowrap="nowrap" align="left">
                    <form action="dns.php" method="POST">
<?
      if ($window) {
?>
                      <input type="hidden" name="window" value="1">
<?
      }
?>
                      <input type="hidden" name="my_index" value="<? echo ($_SESSION[$my_index] - $_SESSION[$my_delta]); ?>">
                      <input type="submit" class="button" value=" Previous " style="width: 100px">
                    </form>
                  </td>
<?
    } else {
?>
                  <td width="20%" class="aba" nowrap="nowrap" align="left">&nbsp;</td>
<?
    }
    if ($_SESSION[$my_index] < $count - $_SESSION[$my_delta]) {
?>
                  <td class="aba" nowrap="nowrap" align="left">
                    <form action="dns.php" method="POST">
<?
      if ($window) {
?>
                      <input type="hidden" name="window" value="1">
<?
      }
?>
                      <input type="hidden" name="my_index" value="<? echo ($_SESSION[$my_index] + $_SESSION[$my_delta]); ?>">
                      <input type="submit" class="button" value=" Next " style="width: 100px">
                    </form>
                  </td>
<?
    } else {
?>
                  <td width="20%" class="aba" nowrap="nowrap" align="left">&nbsp;</td>
<?
    }
    if ($begin > 0) {
?>
                  <td class="aba" nowrap="nowrap" align="left">
                    <form action="dns.php" method="POST">
<?
      if ($window) {
?>
                      <input type="hidden" name="window" value="1">
<?
      }
?>
                      <input type="hidden" name="begin" value="0">
                      <input type="submit" class="button" value=" First " style="width: 100px">
                    </form>
                  </td>
<?
    } else {
?>
                  <td class="aba" nowrap="nowrap" align="left">&nbsp;</td>
<?
    }
  }
?>
                </tr>
                <tr>
                  <th colspan="6" width="10%" align="left" class="item">Showing <? echo $different_ips; ?> different clients</th>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </center></div>
    </td>
  </tr>
<?
  if (!$window) {
?>
  <tr>
    <td>
      <form action="index.php" method="POST">
      <table border="0" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td class="aba" nowrap="nowrap" align="left">
            <input type="submit" class="button" value=" Back to Query " style="width: 100px">
          </td>
        </tr>
      </table>
      </form>
    </td>
  </tr>
<?
  }
?>
</table>
<script language="JavaScript" type="text/javascript"><!--

function open_win(url, query)
{
    var win_location;
    var screen_width, screen_height;
    var win_top, win_left;
    var myWin;
    var win_width = 800;
    var win_height = 400;

    screen_height = 0;
    screen_width = 0;
    win_top = 0;
    win_left = 0;

    if (window.innerWidth) screen_width = window.innerWidth;
    if (window.innerHeight) screen_height = window.innerHeight;

    win_location = url + '?' + 'sid=<?php echo session_id(); ?>&window=1&' + query;

    win_top  = screen_height - win_height - 20;
    win_left = screen_width  - win_width  - 20;
    myWin  = window.open(
        win_location,
        'NewWindow',
        'width='+win_width+',height='+win_height+',top='+win_top+',left='+win_left+',scrollbars=yes'
    );
    myWin.focus();
}
//-->
</script>

</body>
</html>
