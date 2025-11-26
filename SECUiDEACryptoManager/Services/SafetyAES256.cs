using CryptoManager.Services.Helpers;
using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptoManager.Services
{
    public class SafetyAES256 : ICryptoManager, ICryptoKeyManager
    {
        private string key;
        public bool IsKeySetted => !string.IsNullOrEmpty(key);
        private PaddingMode paddingMode;
        private CipherMode cipherMode;
        private int Iterations = 10000; // PBKDF2 반복 횟수

        /// <summary>
        /// 초기 키 없이 SafetyAES256 인스턴스를 초기화
        /// </summary>
        public SafetyAES256() : this(null, CipherMode.CBC, PaddingMode.PKCS7)
        {
        }

        /// <summary>
        /// 지정된 키로 SafetyAES256 인스턴스를 초기화
        /// </summary>
        /// <param name="key">암호화에 사용할 키</param>
        public SafetyAES256(string key) : this(key, CipherMode.CBC, PaddingMode.PKCS7)
        {
        }

        /// <summary>
        /// 지정된 암호화 모드와 패딩 모드로 SafetyAES256 인스턴스를 초기화
        /// </summary>
        /// <param name="cipherMode">암호화 모드</param>
        /// <param name="paddingMode">패딩 모드</param>
        public SafetyAES256(CipherMode cipherMode, PaddingMode paddingMode) : this(null, cipherMode, paddingMode)
        {
        }

        /// <summary>
        /// 모든 옵션을 지정하여 SafetyAES256 인스턴스를 초기화
        /// </summary>
        /// <param name="key">암호화에 사용할 키</param>
        /// <param name="cipherMode">암호화 모드 (기본: CBC)</param>
        /// <param name="paddingMode">패딩 모드 (기본: PKCS7)</param>
        public SafetyAES256(string key, CipherMode cipherMode, PaddingMode paddingMode)
        {
            this.key = key;
            this.cipherMode = cipherMode;
            this.paddingMode = paddingMode;
        }

        #region ICryptoManager Implementation

        public string Encrypt(string plainText)
        {
            if (!IsKeySetted)
                throw new InvalidOperationException("암호화 키가 설정되어 있지 않습니다.");

            return EncryptInternal(plainText, null);
        }

        public string Encrypt(string plainText, string salt)
        {
            if (!IsKeySetted)
                throw new InvalidOperationException("암호화 키가 설정되어 있지 않습니다.");

            AESHelper.ValidateInput(nameof(salt), salt);
            return EncryptInternal(plainText, salt);
        }

        public string Decrypt(string cipherText)
        {
            if (!IsKeySetted)
                throw new InvalidOperationException("암호화 키가 설정되어 있지 않습니다.");

            return DecryptInternal(cipherText, null);
        }

        public string Decrypt(string cipherText, string salt)
        {
            if (!IsKeySetted)
                throw new InvalidOperationException("암호화 키가 설정되어 있지 않습니다.");

            AESHelper.ValidateInput(nameof(salt), salt);
            return DecryptInternal(cipherText, salt);
        }

        #endregion

        #region ICryptoKeyManager Implementation

        public void SetKey(string newKey)
        {
            if (string.IsNullOrEmpty(newKey))
                throw new ArgumentException("키는 비어있을 수 없습니다.", nameof(newKey));

            key = newKey;
        }

        #endregion

        #region Internal Encryption/Decryption

        /// <summary>
        /// 암호화 메서드
        /// </summary>
        /// <param name="plainText">암호화할 평문</param>
        /// <param name="salt">Salt (null 가능)</param>
        /// <returns>Base64로 인코딩된 암호문</returns>
        private string EncryptInternal(string plainText, string salt)
        {
            AESHelper.ValidateInput(nameof(plainText), plainText);

            try
            {
                byte[] keyBytes = DeriveKey(key, salt);

                using (var aes = Aes.Create())
                {
                    AESHelper.ConfigureAes(aes, keyBytes, cipherMode, paddingMode);
                    aes.GenerateIV();

                    byte[] encrypted = AESHelper.PerformEncryption(
                        plainText, keyBytes, aes.IV, cipherMode, paddingMode);
                    byte[] result = AESHelper.CombineIvAndCipherText(aes.IV, encrypted);

                    return Convert.ToBase64String(result);
                }
            }
            catch (Exception ex)
            {
                string errorMessage = salt == null
                    ? "암호화 중 오류가 발생했습니다."
                    : "Salt를 사용한 암호화 중 오류가 발생했습니다.";
                throw new InvalidCastException(errorMessage, ex);
            }
        }

        /// <summary>
        /// 내부 복호화 메서드
        /// </summary>
        /// <param name="cipherText">복호화할 암호문</param>
        /// <param name="salt">Salt (null 가능)</param>
        /// <returns>복호화된 평문</returns>
        private string DecryptInternal(string cipherText, string salt)
        {
            AESHelper.ValidateInput(nameof(cipherText), cipherText);

            try
            {
                byte[] keyBytes = DeriveKey(key, salt);
                byte[] data = Convert.FromBase64String(cipherText);

                var (iv, encrypted) = AESHelper.SeparateIvAndCipherText(data);
                return AESHelper.PerformDecryption(encrypted, keyBytes, iv, cipherMode, paddingMode);
            }
            catch (Exception ex)
            {
                string errorMessage = salt == null
                    ? "복호화 중 오류가 발생했습니다."
                    : "Salt를 사용한 복호화 중 오류가 발생했습니다.";
                throw new InvalidCastException(errorMessage, ex);
            }
        }

        #endregion

        #region Key Derivation

        /// <summary>
        /// 키 파생 함수 - PBKDF2를 사용하여 안전한 키를 생성
        /// </summary>
        /// <param name="password">원본 키</param>
        /// <param name="salt">Salt (null인 경우 기본 키를 직접 사용)</param>
        /// <returns>32바이트 파생 키</returns>
        private byte[] DeriveKey(string password, string salt)
        {
            if (salt == null)
            {
                // Salt가 없는 경우 키를 직접 사용하되 SHA256으로 정규화
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                    return sha256.ComputeHash(passwordBytes);
                }
            }
            else
            {
                // Salt가 있는 경우 PBKDF2 사용
                byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
                using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, Iterations))
                {
                    return pbkdf2.GetBytes(32); // 256비트 = 32바이트
                }
            }
        }

        #endregion
    }
}
