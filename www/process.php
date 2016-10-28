<? include 'common.php'; ?>
<? include 'config.php'; ?>
<?
  if ($_SESSION['refresh']) {
    $_SESSION['window'] = false;
    $_SESSION['refresh'] = false;
    if ($_SERVER['REQUEST_METHOD'] == "POST") {
      /* query type field */
      $_SESSION['type'] = $_POST['type'];
      /* Number of entries per page. */
      $_SESSION[$_SESSION['type'].'_my_delta'] = 60;
      if (isset($_POST[$_SESSION['type'].'_my_delta'])) {
        if (is_numeric($_POST[$_SESSION['type'].'_my_delta']) && $_POST[$_SESSION['type'].'_my_delta'] > 0)
          $_SESSION[$_SESSION['type'].'_my_delta'] = $_POST[$_SESSION['type'].'_my_delta'];
      }
      if (isset($_POST[$_SESSION['type'].'_nat']) && ($_POST[$_SESSION['type'].'_nat'] == "on" || $_POST[$_SESSION['type'].'_nat'] == "off"))
        $_SESSION[$_SESSION['type'].'_nat'] = $_POST[$_SESSION['type'].'_nat'];
      else
        die ("invalid nat option");
      if (isset($_POST[$_SESSION['type'].'_date_from']) && trim($_POST[$_SESSION['type'].'_date_from']) != "")
        $_SESSION[$_SESSION['type'].'_date_from'] = trim($_POST[$_SESSION['type'].'_date_from']);
      if (isset($_POST[$_SESSION['type'].'_date_to']) && trim($_POST[$_SESSION['type'].'_date_to']) != "")
        $_SESSION[$_SESSION['type'].'_date_to'] = trim($_POST[$_SESSION['type'].'_date_to']);
      if ($_SESSION['type'] == "firewall") {
        /* firewall section */
        if (trim($_POST['firewall_ip_src']) != "")
          $_SESSION['firewall_ip_src'] = trim($_POST['firewall_ip_src']);
        else
          $_SESSION['firewall_ip_src'] = "0.0.0.0";
        if (trim($_POST['firewall_ip_dst']) != "")
          $_SESSION['firewall_ip_dst'] = trim($_POST['firewall_ip_dst']);
        else
          $_SESSION['firewall_ip_dst'] = "0.0.0.0";
        if (isset($_POST['firewall_ip_proto']) && ($_POST['firewall_ip_proto'] == IPPROTO_ANY || $_POST['firewall_ip_proto'] == IPPROTO_TCP || $_POST['firewall_ip_proto'] == IPPROTO_UDP))
          $_SESSION['firewall_ip_proto'] = $_POST['firewall_ip_proto'];
        else
          die ("invalid ip proto \"".$_POST['firewall_ip_proto']."\"");
        if (trim($_POST['firewall_spt']) != "")
          $_SESSION['firewall_spt'] = trim($_POST['firewall_spt']);
        else
          $_SESSION['firewall_spt'] = "0";
        if (trim($_POST['firewall_dpt']) != "")
          $_SESSION['firewall_dpt'] = trim($_POST['firewall_dpt']);
        else
          $_SESSION['firewall_dpt'] = "0";
      } else if ($_SESSION['type'] == "dns") {
        /* dns section */
        if (trim($_POST['dns_client']) != "")
          $_SESSION['dns_client'] = trim($_POST['dns_client']);
        else
          $_SESSION['dns_client'] = "0.0.0.0";
        if (trim($_POST['dns_query']) != "")
          $_SESSION['dns_query'] = trim($_POST['dns_query']);
        else
          $_SESSION['dns_query'] = "";
      } else
        die ("invalid type \"".$_POST['type']."\"");

    } else if ($_SERVER['REQUEST_METHOD'] == "GET") {
      if (isset($_GET['window']))
        $_SESSION['window'] = true;
      if (isset($_GET['dns_client'])) {
        /* Retrieve the last FIREWALL search we made */
        $config = $_SESSION['firewall'];
        /* Point this is a DNS query */
        $_SESSION['type'] = "dns";
        /* Setting new parameters for DNS query  */
        $_SESSION['dns_date_from'] = $_SESSION['firewall_date_from'];
        $_SESSION['dns_date_to'] = $_SESSION['firewall_date_to'];
        $_SESSION['dns_client'] = $config['/RESULT/ENTRY/SRC'][$_GET['dns_client']];
        $_SESSION['dns_query'] = "";
      } else if (isset($_GET['firewall_src'])) {
        /* Retrieve the last DNS search we made */
        $config = $_SESSION['dns'];
        /* Point this is a FIREWALL query */
        $_SESSION['type'] = "firewall";
        /* Setting new parameters for FIREWALL query  */
        $_SESSION['firewall_date_from'] = $_SESSION['dns_date_from'];
        $_SESSION['firewall_date_to'] = $_SESSION['dns_date_to'];
        $_SESSION['firewall_ip_src'] = $config['/RESULT/ENTRY/CLIENT'][$_GET['firewall_src']];
        $_SESSION['firewall_ip_dst'] = "0.0.0.0";
        $_SESSION['firewall_ip_proto'] = IPPROTO_ANY;
        $_SESSION['firewall_spt'] = "0";
        $_SESSION['firewall_dpt'] = "0";
      }
      $_SESSION[$_SESSION['type'].'_my_delta'] = 30;
    } else
      die ("Invalid method request!");
?>
<html>

<head>
  <title><? echo ":: ".$program_name." - Processing Query... Please Wait"; ?></title>
  <link href="css.css" type="text/css" rel="stylesheet" />
  <link href="style.css" type="text/css" rel="stylesheet" />
  <script language="javascript" src="common.js"></script>
  <meta http-equiv="refresh" content="1">
</head>

<body bgcolor=#FFFFFF>

<table width="100%" class="maintable">
  <tr>
    <td>
      <div align="center"><center>
        <table width="100%" border="0" cellpadding="1" cellspacing="0" class="lista">
          <tr class="item">
            <th align="left" width=15%>Please wait while your request is being processed...</th>
          </tr>
        </table>
      </div>
    </td>
  </tr>
</table>

</body>
</html>

<?
  } else {
    $dest = $ip_dst[$_SESSION['type']];
    $port = $port_dst[$_SESSION['type']];
    $time_from = strtotime ($_SESSION [$_SESSION['type'].'_date_from']);
    $time_to = strtotime ($_SESSION [$_SESSION['type'].'_date_to']);
    $month = date ("M", $time_from);
    $day = date ("j", $time_from);
    switch ($day)
      {
        case 1:
        case 2:
        case 3:
        case 4:
        case 5:
        case 6:
        case 7:
        case 8:
        case 9:
          $date = $month."  ".$day;
          break;

        default:
          $date = $month." ".$day;
          break;
      }
    $btime = date ("H:i:s", $time_from);
    $etime = date ("H:i:s", $time_to);
    if ($_SESSION['type'] == "firewall")
      {
        $firewall_ip_src = ($_SESSION ['firewall_ip_src'] == "0.0.0.0") ? "" : "  <field name=\"src\">".$_SESSION ['firewall_ip_src']."</field>\r\n";
        $firewall_ip_dst = ($_SESSION ['firewall_ip_dst'] == "0.0.0.0") ? "" : "  <field name=\"dst\">".$_SESSION ['firewall_ip_dst']."</field>\r\n";
        $firewall_ip_proto = ($_SESSION ['firewall_ip_proto'] == "") ? "" : "  <field name=\"proto\">".$_SESSION ['firewall_ip_proto']."</field>\r\n";
        $firewall_spt = ($_SESSION ['firewall_spt'] == "0") ? "" : "  <field name=\"spt\">".$_SESSION ['firewall_spt']."</field>\r\n";
        $firewall_dpt = ($_SESSION ['firewall_dpt'] == "0") ? "" : "  <field name=\"dpt\">".$_SESSION ['firewall_dpt']."</field>\r\n";
        $query =
          "<query type=\"firewall\">\r\n".
          "  <option name=\"nat\">".$_SESSION ['firewall_nat']."</option>\r\n".
          "  <field name=\"date\">".$date."</field>\r\n".
          "  <field name=\"btime\">".$btime."</field>\r\n".
          "  <field name=\"etime\">".$etime."</field>\r\n".
          $firewall_ip_src.
          $firewall_ip_dst.
          $firewall_ip_proto.
          $firewall_spt.
          $firewall_dpt.
          "</query>\r\n".
          "\r\n\r\n";
      }
    else if ($_SESSION['type'] == "dns")
      {
        $dns_client = ($_SESSION ['dns_client'] == "0.0.0.0") ? "" : "  <field name=\"client\">".$_SESSION ['dns_client']."</field>\r\n";
        $dns_query = ($_SESSION ['dns_query'] == "") ? "" : "  <field name=\"query\">".$_SESSION ['dns_query']."</field>\r\n";
        $query =
          "<query type=\"dns\">\r\n".
          "  <option name=\"nat\">".$_SESSION ['dns_nat']."</option>\r\n".
          "  <field name=\"date\">".$date."</field>\r\n".
          "  <field name=\"btime\">".$btime."</field>\r\n".
          "  <field name=\"etime\">".$etime."</field>\r\n".
          $dns_client.
          $dns_query.
          "</query>\r\n".
          "\r\n\r\n";
      }
    $config = send_xml_query($query, $dest, $port, 3600);
    $_SESSION['query'] = $query;
    $_SESSION[$_SESSION['type']] = $config;
    $_SESSION[$_SESSION['type'].'_my_index'] = 0;
    if ($_SESSION['window'])
      header('Location: '.$_SESSION['type'].'.php?window=1');
    else
      header('Location: '.$_SESSION['type'].'.php');
  }
?>