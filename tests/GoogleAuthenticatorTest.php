<?php

namespace Tests\Vectorface;

use Exception;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use Vectorface\GoogleAuthenticator;
use Vectorface\OtpAuth\Parameters\Algorithm;

class GoogleAuthenticatorTest extends TestCase
{
    /**
     * A valid 26-character (128-bit) base32 test secret.
     * TOTP vectors for it are cross-checked against an independent RFC 6238 implementation.
     */
    private const TEST_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEH';

    /* @var GoogleAuthenticator $googleAuthenticator */
    protected $googleAuthenticator;

    protected function setUp() : void
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    public function testItCanBeInstantiated()
    {
        $ga = new GoogleAuthenticator();

        $this->assertInstanceOf(GoogleAuthenticator::class, $ga);
    }

    /**
     * @throws Exception
     */
    public function testCreateSecretDefaultsToThirtyTwoCharacters()
    {
        $ga = $this->googleAuthenticator;
        $secret = $ga->createSecret();

        $this->assertEquals(32, strlen($secret));
    }

    public function secretLengthProvider()
    {
        $cases = [];
        foreach (range(0, 200) as $length) {
            $cases["length {$length}"] = [$length];
        }
        return $cases;
    }

    /**
     * @dataProvider secretLengthProvider
     * @param int $secretLength
     * @throws Exception
     */
    public function testCreateSecretLengthCanBeSpecified(int $secretLength)
    {
        $ga = $this->googleAuthenticator;

        if ($secretLength < 26 || $secretLength > 128) {
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('Bad secret length');
        }

        $secret = $ga->createSecret($secretLength);

        $this->assertEquals(strlen($secret), $secretLength);
    }

    public function codeProvider()
    {
        // Secret, timeSlice, code, passes
        return [
            // RFC 6238 Appendix B SHA-1 reference vectors. Secret is base32("12345678901234567890");
            // the published codes are 8 digits, so the default 6-digit code is their last 6 digits.
            'RFC6238 T=1'        => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1, '287082', true],
            'RFC6238 T=37037036' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 37037036, '081804', true],
            'RFC6238 T=37037037' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 37037037, '050471', true],
            'RFC6238 T=41152263' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 41152263, '005924', true],
            'RFC6238 T=66666666' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 66666666, '279037', true],
            'RFC6238 wrong code' => ['GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 1, '000000', false],

            // A 26-character (128-bit) secret, the minimum allowed length. Expected codes
            // are cross-checked against an independent RFC 6238 implementation.
            'min secret @0'      => [self::TEST_SECRET, 0, '154113', true],
            'min secret @1'      => [self::TEST_SECRET, 1, '744635', true],
            'min secret @1e6'    => [self::TEST_SECRET, 1000000, '353333', true],
            'min secret wrong'   => [self::TEST_SECRET, 1000000, '000000', false],
        ];
    }

    /**
     * @dataProvider codeProvider
     * @param string $secret
     * @param int|null $timeSlice
     * @param string $code
     * @param bool $passes
     * @throws Exception
     */
    public function testGetCodeReturnsCorrectValues(string $secret, ?int $timeSlice, string $code, bool $passes)
    {
        $generatedCode = $this->googleAuthenticator->getCode($secret, $timeSlice);

        if ($passes) {
            $this->assertEquals($code, $generatedCode);
        } else {
            $this->assertNotEquals($code, $generatedCode);
        }
    }

    /**
     * @throws Exception
     */
    public function testGetQRCodeUrl()
    {
        $secret = self::TEST_SECRET;
        $name = 'Test';
        $url = $this->googleAuthenticator->getQRCodeUrl($name, $secret);

        $prefix = 'data:image/png;base64,';
        $this->assertStringStartsWith($prefix, $url);

        $base64part = substr($url, strlen($prefix));
        $this->assertMatchesRegularExpression("#^[a-zA-Z0-9/+]*={0,2}$#", $base64part);
    }

    /**
     * @throws Exception
     */
    public function testVerifyCode()
    {
        // Good result
        $secret = self::TEST_SECRET;
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(true, $result);

        // Wrong length
        $code = 'INVALIDCODE';
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);

        // Wrong code
        $code = '123456';
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);

        // Bad secret
        $result = $this->googleAuthenticator->verifyCode('', $code);
        $this->assertEquals(false, $result);
    }

    /**
     * @throws Exception
     */
    public function testVerifyCodeWithLeadingZero()
    {
        $secret = self::TEST_SECRET;
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(true, $result);

        $code = '0'.$code;
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertEquals(false, $result);
    }

    /**
     * @throws Exception
     */
    public function testVerifyCodeWithEightDigits()
    {
        $secret = self::TEST_SECRET;
        $ga = $this->googleAuthenticator->setCodeLength(8);

        $code = $ga->getCode($secret);
        $this->assertEquals(8, strlen($code));
        $this->assertTrue($ga->verifyCode($secret, $code));

        // A 6-digit code must not verify when 8 digits are configured
        $this->assertFalse($ga->verifyCode($secret, substr($code, 0, 6)));
    }

    /**
     * @throws Exception
     */
    public function testVerifyCodeRejectsNonNumericCode()
    {
        $secret = self::TEST_SECRET;

        $this->assertFalse($this->googleAuthenticator->verifyCode($secret, 'abcdef'));
        $this->assertFalse($this->googleAuthenticator->verifyCode($secret, '12345x'));
        $this->assertFalse($this->googleAuthenticator->verifyCode($secret, "12345\n"));
    }

    /**
     * @throws Exception
     */
    public function testVerifyCodeReportsMatchedTimeSlice()
    {
        $secret = self::TEST_SECRET;
        $currentTimeSlice = (int) floor(time() / 30);

        // A code from the previous time slice should match at $currentTimeSlice - 1
        $code = $this->googleAuthenticator->getCode($secret, $currentTimeSlice - 1);
        $matchedTimeSlice = null;
        $result = $this->googleAuthenticator->verifyCode($secret, $code, 1, $matchedTimeSlice);

        $this->assertTrue($result);
        $this->assertSame($currentTimeSlice - 1, $matchedTimeSlice);

        // On failure, the matched time slice must remain untouched
        $matchedTimeSlice = null;
        $this->assertFalse($this->googleAuthenticator->verifyCode($secret, '000000', 0, $matchedTimeSlice));
        $this->assertNull($matchedTimeSlice);
    }

    public function invalidDiscrepancyProvider()
    {
        return [
            'Negative' => [-1],
            'Too large' => [61],
        ];
    }

    /**
     * @dataProvider invalidDiscrepancyProvider
     * @param int $discrepancy
     * @throws Exception
     */
    public function testVerifyCodeRejectsOutOfRangeDiscrepancy(int $discrepancy)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Discrepancy must be between 0 and 60 time slices');

        $this->googleAuthenticator->verifyCode(self::TEST_SECRET, '123456', $discrepancy);
    }

    public function testSetCodeLength()
    {
        $result = $this->googleAuthenticator->setCodeLength(6);

        $this->assertInstanceOf(GoogleAuthenticator::class, $result);
    }

    public function invalidCodeLengthProvider()
    {
        return [
            'Too short' => [5],
            'Too long' => [9],
            'Zero' => [0],
            'Negative' => [-1],
        ];
    }

    /**
     * @dataProvider invalidCodeLengthProvider
     * @param int $length
     */
    public function testSetCodeLengthRejectsOutOfRangeValues(int $length)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Code length must be between 6 and 8');

        $this->googleAuthenticator->setCodeLength($length);
    }

    public function badSecretProvider()
    {
        return [
            "Empty secrets not allowed" => [''],
            "Only allows uppercase letters" => ['n'],
            "Not correct number of = padding" => ['=='],
            "Padding = should only appear at the end" => ['===A==='],
        ];
    }

    /**
     * @dataProvider badSecretProvider
     * @param string $secret
     * @throws Exception
     */
    public function testGetCodeWithBadSecret(string $secret)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Could not decode secret');

        $code = $this->googleAuthenticator->getCode($secret);
        $this->assertEquals('', $code);
    }

    public function shortSecretProvider()
    {
        return [
            "3-byte (24-bit) secret" => ['SECRET'],
            "10-byte (80-bit) secret" => ['JBSWY3DPEHPK3PXP'],
            "15-byte (120-bit) secret" => ['JBSWY3DPEHPK3PXPJBSWY3DP'],
        ];
    }

    /**
     * @dataProvider shortSecretProvider
     * @param string $secret
     * @throws Exception
     */
    public function testGetCodeRejectsSecretsShorterThan128Bits(string $secret)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Secret must be at least 128 bits');

        $this->googleAuthenticator->getCode($secret);
    }

    /**
     * Ensure URL builder emits correctly with minimal params
     * @return void
     */
    public function testUriBuilderDefaults()
    {
        $builder = $this->googleAuthenticator->getUriBuilder()
            ->account("foo")
            ->secret("bar");

        $this->assertEquals("otpauth://totp/foo?secret=bar", "$builder");
    }

    /**
     * Ensure URL builder emits all params correctly
     *
     * @return void
     * @throws Exception
     */
    public function testUriBuilderParams()
    {
        $secret = $this->googleAuthenticator->createSecret();
        $digits = 8;
        $period = 60;
        $algorithm = Algorithm::SHA256;
        $builder = $this->googleAuthenticator
            ->setCodeLength(8)
            ->getUriBuilder()
                ->account("foo")
                ->secret($secret)
                ->issuer("bar+baz&quux")
                ->algorithm($algorithm)
                ->period($period);

        $this->assertEquals(
            "otpauth://totp/bar%2Bbaz%26quux:%20foo?secret={$secret}&issuer=bar%2Bbaz%26quux&algorithm={$algorithm->value}&digits={$digits}&period={$period}",
            "$builder"
        );
    }
}
