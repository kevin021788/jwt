<?php 
namespace Kevin\Jwt;

use \DomainException;
use \InvalidArgumentException;
use \UnexpectedValueException;
use \DateTime;

/**
 * @category Authentication
 * @author   Kevin Zeng <kevin0217@126.com>
 * @link     https://github.com/kevin021788/jwt
 * Class JWT
 * @package Kevin\Jwt
 */
class  JWT {

    private $_secret;
    private $_header;
    private $_payload;
    private $_alg;
    private $_keyId;
    private $_head;
    private $_token;
    private $_timestamp = null;
    private $_leeway = 0;


    public static $supported_alg = array(
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'RS256' => array('openssl', 'SHA256'),
        'RS512' => array('openssl', 'SHA512'),
        'RS384' => array('openssl', 'SHA384'),
    );

    public function __construct()
    {
        if(empty($this->getAlg())) $this->setAlg('HS256');

        if(empty($this->getSecret())) $this->setSecret('ASd3_faf_bas3d_as2df_fa7sd');

        $_header = array('typ' => 'JWT', 'alg' => $this->getAlg());

        if(!empty($this->getKeyId())) $_header['kid'] = $this->getKeyId();

        if(!empty($this->getHead()) && is_array($this->getHead())) $_header = array_merge($this->getHead(), $_header);

        $this->setHeader($_header);

        if(is_null($this->getTimestamp())) $this->setTimestamp(time());


    }

    public function getAlg()
    {
        return $this->_alg;
    }

    public function setAlg($_alg)
    {
        $this->_alg = $_alg;
    }

    public function getKeyId()
    {
        return $this->_keyId;
    }

    public function setKeyId($_keyId)
    {
        $this->_keyId = $_keyId;
    }

    public function getSecret()
    {
        return $this->_secret;
    }

    public function setSecret($_secret)
    {
        $this->_secret = $_secret;
    }

    public function getPayload()
    {
        return $this->_payload;
    }

    public function setPayload($_payload)
    {
        $this->_payload = $_payload;
    }

    private function getHeader()
    {
        return $this->_header;
    }

    private function setHeader($_header)
    {
        $this->_header = $_header;
    }

    public function getHead()
    {
        return $this->_head;
    }

    public function setHead($_head)
    {
        $this->_head = $_head;
    }

    public function getToken()
    {
        return $this->_token;
    }

    public function setToken($_token)
    {
        $this->_token = $_token;
    }

    public function getTimestamp()
    {
        return $this->_timestamp;
    }

    public function setTimestamp($_timestamp)
    {
        $this->_timestamp = $_timestamp;
    }

    public function encode()
    {
        $res = array();

        $res[] = self::urlSafeB64Encode(self::jsonEncode($this->getHeader()));
        $res[] = self::urlSafeB64Encode(self::jsonEncode($this->getPayload()));
        $str = implode('.', $res);
        $sign = $this->sign($str);
        $res[] = self::urlSafeB64Encode($sign);
        return implode('.', $res);
    }

    public function decode()
    {
        $jwt = explode('.', $this->getToken());

        if (count($jwt) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }

        if (empty($this->getSecret())) {
            throw new InvalidArgumentException('secret may not by empty');
        }

        list($head64, $payload64, $sign64) = explode('.', $this->getToken());


        if (null === ($head = self::jsonDecode(self::urlSafeB64Decode($head64)))) {
            throw new UnexpectedValueException('Invalid header encodeing');
        }
        if (null === ($payload = self::jsonDecode(self::urlSafeB64Decode($payload64)))) {
            throw new UnexpectedValueException('Invalid payload encodeing');
        }
        if (null === ($sign = self::urlSafeB64Decode($sign64))) {
            throw new UnexpectedValueException('Invalid signature encodeing');
        }
        if (empty($head->alg)) {
            throw new UnexpectedValueException('Empty algorithm');
        }
        if (empty(self::$supported_alg[$head->alg])) {
            throw new UnexpectedValueException('Algorithm not support');
        }
        if (in_array($head->alg, self::$supported_alg)) {
            throw new UnexpectedValueException('Algorithm not allowed');
        }

    }

    public function sign($str)
    {
        if (empty(self::$supported_alg[$this->getAlg()])) {
            throw new DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = self::$supported_alg[$this->getAlg()];

        switch ($function) {

            case 'hash_hmac':
                return hash_hmac($algorithm, $str, $this->getSecret(), true);

            case 'openssl':
                $signature = '';
                $success = openssl_sign($str, $signature, $this->getSecret(), $algorithm);
                if (!$success) {
                    throw new DomainException('OpenSSL unable to sign data');
                } else {
                    return $signature;
                }
        }

    }

    private static function verify($text,$signature,$key,$alg)
    {
        if (empty(self::$supported_alg[$alg])) {
            throw new DomainException('Algorithm not supported');
        }
        list($function, $algorithm) = self::$supported_alg[$alg];

        switch ($function) {
            case 'openssl':
                $success = openssl_verify($text, $signature, $key, $algorithm);
                if ($success == 1) {
                    return true;
                } elseif ($success == 0) {
                    return false;
                }
                throw new DomainException('Openssl Error:' . openssl_error_string());
            case 'hash_hmac':
            default:
                $hash = hash_hmac($algorithm, $text, $key, true);
                if (function_exists('hash_equals')) {
                    return hash_equals($signature, $hash);
                }
        }
    }

    private static function jsonEncode($arr)
    {
        $json = json_encode($arr);
        if (function_exists('json_last_error') && $errNo = json_last_error()) {
            self::handleJsonError($errNo);
        } elseif($json === 'null' && $arr!== null) {
            throw new DomainException('Null result with not non-null input');
        }
        return $json;
    }

    private static function jsonDecode($str)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            /** In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
             * to specify that large ints (like Steam Transaction IDs) should be treated as
             * strings, rather than the PHP default behaviour of converting them to floats.
             */
            $obj = json_decode($str, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            /** Not all servers will support that, however, so for older versions we must
             * manually detect large ints in the JSON string and quote them (thus converting
             *them to strings) before decoding, hence the preg_replace() call.
             */
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $str);
            $obj = json_decode($json_without_bigints);
        }
        if (function_exists('json_last_error') && $errNo = json_last_error()) {
            static::handleJsonError($errNo);
        } elseif ($obj === null && $str !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Url Safe Base64 Encode
     * @param $str
     * @return mixed
     */
    private static function urlSafeB64Encode($str)
    {
        return str_replace('=', '', strtr(base64_encode($str), '+/', '-_'));
    }

    /**
     * Url Safe Base64 Decode
     * @param $str
     * @return bool|string
     */
    private static function urlSafeB64Decode($str)
    {
        $mod = strlen($str) % 4;
        if ($mod) {
            $padLen = 4 - $mod;
            $str .= str_repeat('=', $padLen);
        }
        return base64_decode(strtr($str, '-_', '+/'));
    }

    private static function handleJsonError($errNo)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters' //PHP >= 5.3.3
        );
        throw new DomainException(
            isset($messages[$errNo])
                ? $messages[$errNo]
                : 'Unknown JSON error: ' . $errNo
        );
    }

    private static function safeStrlen($str)
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str,'8bit');
        }
        return strlen($str);
    }

}
?>