<?php
include '../lib/common.php';

$session_id = (!empty($_POST['session_id'])) ? preg_replace("/[^0-9]/", "", $_POST['session_id']) : false;
$signature = (!empty($_POST['signature'])) ? hex2bin($_POST['signature']) : false;
$nonce = (!empty($_POST['nonce'])) ? preg_replace("/[^0-9]/", "", $_POST['nonce']) : false;
$commands = (!empty($_POST['commands'])) ? json_decode($_POST['commands'], true) : false;
$api_key = (!empty($_POST['api_key'])) ? preg_replace("/[^0-9a-zA-Z]/", "", $_POST['api_key']) : false;
$api_signature = (!empty($_POST['api_signature'])) ? preg_replace("/[^0-9a-zA-Z]/", "", $_POST['api_signature']) : false;

$CFG->language = (!empty($_POST['lang']) && in_array(strtolower($_POST['lang']), array('en', 'es', 'ru', 'zh'))) ? strtolower($_POST['lang']) : false;

$return = array();

// Authenticate session
if ($session_id) {
    $result = db_query_array('SELECT sessions.nonce AS nonce, sessions.session_key AS session_key, sessions.awaiting AS awaiting, site_users.* FROM sessions LEFT JOIN site_users ON (sessions.user_id = site_users.id) WHERE sessions.session_id = ' . $session_id);

    if (!empty($result)) {
        if (!empty($_POST['commands']) && openssl_verify($_POST['commands'], $signature, $result[0]['session_key'])) {
            User::setInfo($result[0]);
            if (User::$info['locked'] == 'Y' || User::$info['deactivated'] == 'Y') {
                $CFG->session_locked = true;
                $return['error'] = 'account-locked-or-deactivated';
            } else {
                $CFG->session_active = true;
            }
            if (empty($CFG->language)) {
                $CFG->language = $result[0]['last_lang'];
            }
        } else {
            $return['error'] = 'invalid-signature';
        }
    } else {
        $return['error'] = 'session-not-found';
    }
}

// Verify API key
if ($api_key && $api_signature) {
    $result = db_query_array('SELECT api_keys.id AS key_id, api_keys.secret AS secret, api_keys.view AS p_view, api_keys.orders AS p_orders, api_keys.withdraw AS p_withdraw, site_users.* FROM api_keys LEFT JOIN site_users ON (api_keys.site_user = site_users.id) WHERE api_keys.key = "' . $api_key . '"');

    if (!empty($result)) {
        $hash = hash_hmac('sha256', $_POST['raw_params_json'], $result[0]['secret']);
        if ($api_signature == $hash) {
            User::setInfo($result[0]);
            if (empty($CFG->language)) {
                $CFG->language = $result[0]['last_lang'];
            }
            if (User::$info['locked'] == 'Y' || User::$info['deactivated'] == 'Y') {
                $return['error'] = 'account-locked-or-deactivated';
                $CFG->session_locked = true;
            } else {
                $CFG->session_active = true;
                $CFG->session_api = true;
            }
        } else {
            $return['error'] = 'AUTH_INVALID_SIGNATURE';
        }
    } else {
        $return['error'] = 'AUTH_INVALID_KEY';
    }
}

// Execute commands
if (is_array($commands)) {
    foreach ($commands as $classname => $methods_arr) {
        if (is_array($methods_arr)) {
            foreach ($methods_arr as $method => $args) {
                $classname = preg_replace("/[^0-9a-zA-Z_]/", "", $classname);
                $method = preg_replace("/[^0-9a-zA-Z_]/", "", $method);
                if (is_array($args)) {
                    foreach ($args as $i => $arg) {
                        $args[$i] = preg_replace("/[^0-9a-zA-Z!@#$%&*?\.\-_]/", "", $arg);
                    }
                } else {
                    $args = array();
                }
                $response = call_user_func_array(array($classname, $method), $args);
                $return[$classname][$method]['results'][] = $response;
            }
        }
    }
}

// Update session nonce
if ($CFG->session_active && $nonce) {
    $result[0]['nonce'] = $nonce + 1;
    db_update('sessions', $session_id, array('nonce' => ($nonce + 1), 'session_time' => date('Y-m-d H:i:s')), 'session_id');
}

echo json_encode($return);
