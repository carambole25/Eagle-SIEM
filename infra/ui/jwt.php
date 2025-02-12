<?php

function base64UrlEncode($data) {
    return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
}

function base64UrlDecode($data)
{
    $base64 = strtr($data, '-_', '+/');
    $base64Padded = str_pad($base64, strlen($base64) % 4, '=', STR_PAD_RIGHT);
    return base64_decode($base64Padded);
}

function createToken($username){
    $base64UrlHeader = base64UrlEncode(json_encode(["alg" => "HS256", "typ" => "JWT"]));
    $base64UrlPayload = base64UrlEncode(json_encode(["user" => $username]));
    $base64UrlSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, "changeme_MYSQL_PASSWORD", true);
    $base64UrlSignature = base64UrlEncode($base64UrlSignature);
    return $base64UrlHeader . '.' . $base64UrlPayload . '.' . $base64UrlSignature;
}

function validateToken($token){
    list($base64UrlHeader, $base64UrlPayload, $base64UrlSignature) = explode('.', $token);

    $signature = base64UrlDecode($base64UrlSignature);
    $expectedSignature = hash_hmac('sha256', $base64UrlHeader . '.' . $base64UrlPayload, "changeme_MYSQL_PASSWORD", true);

    return hash_equals($signature, $expectedSignature);
}

?>