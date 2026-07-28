<?php

namespace Vectorface;

use Endroid\QrCode\Builder\Builder;
use Endroid\QrCode\Writer\PngWriter;
use Exception;
use InvalidArgumentException;
use Vectorface\OtpAuth\Base32;
use Vectorface\OtpAuth\UriBuilder;

/**
 * PHP Class for handling Google Authenticator 2-factor authentication
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 * @link http://www.phpgangsta.de/
 * @link https://github.com/PHPGangsta/GoogleAuthenticator
 */
class GoogleAuthenticator
{
    protected int $_codeLength = 6;

    /**
     * Create new secret.
     * Defaults to 32 characters (160 bits), randomly chosen from the allowed base32 characters.
     *
     * @throws InvalidArgumentException if the requested length is out of the 26-128 range
     * @throws Exception if no source of secure randomness is available
     */
    public function createSecret(int $secretLength = 32) : string
    {
        // RFC 4226 requires a shared secret of at least 128 bits; cap at 640 bits.
        // 26 base32 characters encode 128 bits, 128 characters encode 640 bits.
        if ($secretLength < 26 || $secretLength > 128) {
            throw new InvalidArgumentException('Bad secret length');
        }

        // Each base32 character encodes 5 bits. Round the byte count up so we always have enough
        // entropy to fill the requested number of characters, then trim to the exact length.
        $rnd = random_bytes((int) ceil($secretLength * 5 / 8));

        // Strip padding so the secret is a clean base32 string, then trim to the requested length.
        return substr(rtrim(Base32::encode($rnd), '='), 0, $secretLength);
    }

    /**
     * Calculate the code, with given secret and point in time
     *
     * @throws InvalidArgumentException if the secret is not valid base32 or is shorter than 128 bits
     */
    public function getCode(string $secret, ?int $timeSlice = null) : string
    {
        if ($timeSlice === null) {
            $timeSlice = (int) floor(time() / 30);
        }

        $secretkey = Base32::decode($secret);
        if ($secretkey === null || $secretkey === '') {
            throw new InvalidArgumentException('Could not decode secret');
        }

        // RFC 4226: the shared secret MUST be at least 128 bits (16 bytes).
        if (strlen($secretkey) < 16) {
            throw new InvalidArgumentException('Secret must be at least 128 bits');
        }

        // Pack time into binary string
        $time = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpack binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->_codeLength);

        return str_pad((string) ($value % $modulo), $this->_codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * Get QR-Code URL for image, from our native QRCode API
     *
     * @param string $account Account Name
     * @param string $secret A base32-encoded secret (rfc3548)
     * @param string|null $issuer The provider or issuer with which the account is associated (optional)
     * @return string Generate a QRCode for a given string
     * @throws Exception on encoding error
     */
    public function getQRCodeUrl(string $account, string $secret, ?string $issuer = null) : string
    {
        $uri = $this->getUriBuilder()
            ->issuer($issuer)
            ->account($account)
            ->secret($secret)
            ->getUri();
        return $this->getQRCodeDataUri($uri);
    }

    /**
     * Build an OTP URI using the builder pattern
     */
    public function getUriBuilder(): UriBuilder
    {
        $builder = new UriBuilder();
        if ($this->_codeLength !== 6) {
            $builder->digits($this->_codeLength);
        }
        return $builder;
    }

    /**
     * Generate a QRCode for a given string
     *
     * @param string $uri to encode into a QRCode
     * @return string binary data of the PNG of the QRCode
     * @throws Exception
     */
    protected function getQRCodeDataUri(string $uri) : string
    {
        return (new Builder(
            data: $uri,
            writer: new PngWriter,
            size: 260,
            margin: 10,
        ))->build()->getDataUri();
    }

    /**
     * Check if the code is correct. This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
     *
     * @param int $discrepancy This is the allowed time drift in 30 second units (8 means 4 minutes before or after)
     * @param int|null $matchedTimeSlice Set to the time slice that matched on success; persist the last accepted
     *                                   slice and reject codes matching a slice <= that value to prevent replay
     * @throws InvalidArgumentException if $discrepancy is out of the 0-60 range
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, ?int &$matchedTimeSlice = null) : bool
    {
        if ($discrepancy < 0 || $discrepancy > 60) {
            throw new InvalidArgumentException('Discrepancy must be between 0 and 60 time slices');
        }

        $currentTimeSlice = (int) floor(time() / 30);

        if (strlen($code) !== $this->_codeLength || !ctype_digit($code)) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            try {
                $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            } catch (Exception) {
                return false;
            }

            if (hash_equals($calculatedCode, $code)) {
                $matchedTimeSlice = $currentTimeSlice + $i;
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length, must be between 6 and 8 (RFC 4226)
     *
     * @throws InvalidArgumentException
     */
    public function setCodeLength(int $length) : self
    {
        if ($length < 6 || $length > 8) {
            throw new InvalidArgumentException('Code length must be between 6 and 8');
        }
        $this->_codeLength = $length;
        return $this;
    }
}

