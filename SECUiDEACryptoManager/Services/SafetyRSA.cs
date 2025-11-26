using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptoManager.Services
{
    /// <summary>
    /// RSA 공개키 암호화 구현체 (OAEP 패딩 사용)
    /// 2048-bit 키 사용으로 안전성 확보
    /// 주의: RSA는 데이터 크기 제한이 있으므로 대용량 데이터는 SafetyHybridRSA 사용 권장
    /// </summary>
    public class SafetyRSA : ICryptoManager, IDisposable
    {
        private readonly RSA _rsa;
        private readonly int _keySize;
        private const int DefaultKeySize = 2048;
        private const string DecryptWithoutPrivateKeyMessage = "개인키 없이는 복호화할 수 없습니다.";
        private const string DataTooLargeMessage = "데이터가 너무 큽니다. RSA로 암호화 가능한 최대 크기를 초과했습니다.";

        #region Constructors

        /// <summary>
        /// 새로운 RSA 키 쌍 생성
        /// </summary>
        /// <param name="keySize">키 크기 (기본: 2048 bit)</param>
        public SafetyRSA(int keySize = DefaultKeySize)
        {
            _keySize = keySize;
            _rsa = RSA.Create();
            _rsa.KeySize = keySize;
        }

        /// <summary>
        /// 기존 키로 초기화 (XML 형식)
        /// </summary>
        /// <param name="xmlKey">RSA 키 (공개키 또는 개인키 포함)</param>
        public SafetyRSA(string xmlKey)
        {
            if (string.IsNullOrEmpty(xmlKey))
                throw new ArgumentException("XML 키는 비어있을 수 없습니다.", nameof(xmlKey));

            _rsa = RSA.Create();
            _rsa.FromXmlString(xmlKey);
            _keySize = _rsa.KeySize;
        }

        #endregion

        #region ICryptoManager Implementation

        /// <summary>
        /// 공개키로 암호화 (OAEP SHA256 패딩 사용)
        /// </summary>
        /// <param name="plainText">암호화할 평문</param>
        /// <returns>Base64 인코딩된 암호문</returns>
        public string Encrypt(string plainText)
        {
            ValidateInput(nameof(plainText), plainText);

            try
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

                // 데이터 크기 체크
                if (plainBytes.Length > MaxDataSize)
                {
                    throw new ArgumentException(
                        $"{DataTooLargeMessage} (최대: {MaxDataSize} 바이트, 현재: {plainBytes.Length} 바이트)");
                }

                byte[] encryptedBytes = _rsa.Encrypt(plainBytes, RSAEncryptionPadding.OaepSHA256);
                return Convert.ToBase64String(encryptedBytes);
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException("RSA 암호화 중 오류 발생", ex);
            }
        }

        /// <summary>
        /// Salt는 RSA에서 사용하지 않음 (OAEP가 자동으로 랜덤성 추가)
        /// </summary>
        public string Encrypt(string plainText, string salt)
        {
            // RSA OAEP는 내부적으로 랜덤 패딩을 사용하므로 salt 불필요
            return Encrypt(plainText);
        }

        /// <summary>
        /// 개인키로 복호화
        /// </summary>
        /// <param name="cipherText">복호화할 암호문 (Base64)</param>
        /// <returns>복호화된 평문</returns>
        public string Decrypt(string cipherText)
        {
            ValidateInput(nameof(cipherText), cipherText);

            try
            {
                byte[] encryptedBytes = Convert.FromBase64String(cipherText);
                byte[] decryptedBytes = _rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.OaepSHA256);
                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException(DecryptWithoutPrivateKeyMessage, ex);
            }
        }

        /// <summary>
        /// Salt는 RSA에서 사용하지 않음
        /// </summary>
        public string Decrypt(string cipherText, string salt)
        {
            return Decrypt(cipherText);
        }

        #endregion

        #region Key Management

        /// <summary>
        /// 공개키 내보내기 (XML 형식)
        /// </summary>
        public string ExportPublicKey()
        {
            return _rsa.ToXmlString(false);
        }

        /// <summary>
        /// 개인키 내보내기 (XML 형식) - 주의: 안전하게 보관해야 함!
        /// </summary>
        public string ExportPrivateKey()
        {
            return _rsa.ToXmlString(true);
        }

        /// <summary>
        /// PEM 형식으로 공개키 내보내기 (.NET 5.0+)
        /// </summary>
        public string ExportPublicKeyPEM()
        {
#if NET5_0_OR_GREATER
            return _rsa.ExportRSAPublicKeyPem();
#else
            throw new NotSupportedException("PEM 내보내기는 .NET 5.0 이상에서 지원됩니다.");
#endif
        }

        /// <summary>
        /// PEM 형식으로 개인키 내보내기 (.NET 5.0+)
        /// </summary>
        public string ExportPrivateKeyPEM()
        {
#if NET5_0_OR_GREATER
            return _rsa.ExportRSAPrivateKeyPem();
#else
            throw new NotSupportedException("PEM 내보내기는 .NET 5.0 이상에서 지원됩니다.");
#endif
        }

        #endregion

        #region Properties

        /// <summary>
        /// 최대 암호화 가능한 데이터 크기 (바이트)
        /// RSA는 키 크기에 따라 암호화 가능한 데이터 크기 제한
        /// OAEP SHA256 패딩 사용 시: (keySize / 8) - 66
        /// </summary>
        public int MaxDataSize => (_keySize / 8) - 66;

        /// <summary>
        /// RSA 키 크기 (비트)
        /// </summary>
        public int KeySize => _keySize;

        #endregion

        #region Helper Methods

        /// <summary>
        /// 입력 값 검증
        /// </summary>
        private static void ValidateInput(string paramName, string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException($"{paramName}는 비어있을 수 없습니다.", paramName);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            _rsa?.Dispose();
        }

        #endregion
    }
}
