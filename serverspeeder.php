<?php
if ($argc < 4) {
        echo "Usage: php " . $argv[0] . " mac expireYear bandwidth, Bandwidth=0 means unlimited.\nExample: php " . $argv[0] . " 04:a0:67:a1:05:0b 2999 0 \n";
        die;
}
$lic_tpl = 'b226bc274e220f53e22d863a1ec913dea6961bd046d034e88818e68d260d781345298b8d3b11e00b5061045667c12af4982992ab86ee7a4f84c1ef83020a1adc[serial]c81cb3b404eab69f59993fbf62bd373a[date]0663cea3f326[bw]a366445113ecf74205e40af32cb30c5342cc5ebd981f7e02a9326f3823e8304e4d20f942f20bdfbeaeeff843';
// month/date base: FA43 now 0663 => 1231 we do not change it
$date_base = 16245;
$bw_base = 3812869942;
$mac = $argv[1];
$date = intval($argv[2]);
$bw = intval($argv[3]);
$mac = explode(':', $mac);
$mac_res = array();
for ($i = 0; $i < 16; $i++) {
        if ($i < 6) {
                $mac_res[$i] = intval($mac[$i], 16) + $i;
        } else {
                $mac_res[$i] = $mac_res[$i % 6] + $i;
        }
}
$serial = '';
for ($i = 0; $i < 8; $i++) {
        $serial .= sprintf('%02X', ($mac_res[$i] + $mac_res[$i + 8]) % 256);
}
echo 'SerialNo:' . $serial . '
';
$lic = '';
$rd = array(162, 15, 239, 202, 57, 14, 45, 164, 147, 232, 120, 90, 117, 15, 239, 232);
for ($i = 0; $i < 16; $i++) {
        $lic .= sprintf('%02x', (ord($serial[$i]) + $rd[$i]) % 256);
}
echo 'Lic:' . $lic . '
';
$date_lic = unpack('H*', pack('v', $date_base + $date));
$date_lic = $date_lic[1];
$bw_lic = unpack('H*', pack('V', $bw_base + $bw));
$bw_lic = $bw_lic[1];
$lic = str_replace('[serial]', $lic, $lic_tpl);
$lic = str_replace('[date]', $date_lic, $lic);
$lic = str_replace('[bw]', $bw_lic, $lic);
@file_put_contents("./apx-" . $date . "1231.lic", pack('H*', $lic));
