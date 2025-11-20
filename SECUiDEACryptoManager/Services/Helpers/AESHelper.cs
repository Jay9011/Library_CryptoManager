using System;
using System.Security.Cryptography;
using System.Text;

namespace SECUiDEACryptoManager.Services.Helpers
{
    /// <summary>
    /// AES 암복호화 공통 유틸리티
    /// SafetyAES256, SafetyHybridRSA 등에서 재사용
    /// </summary>
    internal static class AESHelper
    {
        private const int IvSize = 16;

        #region Validation

        /// <summary>
        /// 입력 값 검증
        /// </summary>
        public static void ValidateInput(string paramName, string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException($"{paramName}는 비어있을 수 없습니다.", paramName);
        }

        /// <summary>
        /// 키 바이트 검증
        /// </summary>
        public static void ValidateKey(byte[] key)
        {
            if (key == null || key.Length != 32)
                throw new ArgumentException("키는 32바이트여야 합니다.", nameof(key));
        }

        #endregion

        #region AES Configuration

        /// <summary>
        /// AES 객체 설정
        /// </summary>
        public static void ConfigureAes(Aes aes, byte[] key, CipherMode mode, PaddingMode padding)
        {
            aes.Key = key;
            aes.Mode = mode;
            aes.Padding = padding;
        }

        #endregion

        #region IV and CipherText Combination

        /// <summary>
        /// IV와 암호문을 합치는 메서드
        /// </summary>
        /// <param name="iv">초기화 벡터</param>
        /// <param name="cipherText">암호문</param>
        /// <returns>IV + 암호문</returns>
        public static byte[] CombineIvAndCipherText(byte[] iv, byte[] cipherText)
        {
            byte[] result = new byte[iv.Length + cipherText.Length];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(cipherText, 0, result, iv.Length, cipherText.Length);
            return result;
        }

        /// <summary>
        /// IV와 암호문을 분리
        /// </summary>
        /// <param name="data">IV + 암호문</param>
        /// <returns>분리된 IV와 암호문</returns>
        public static (byte[] iv, byte[] cipherText) SeparateIvAndCipherText(byte[] data)
        {
            if (data.Length < IvSize)
                throw new ArgumentException("데이터가 너무 짧습니다. IV를 추출할 수 없습니다.");

            byte[] iv = new byte[IvSize];
            byte[] cipherText = new byte[data.Length - IvSize];

            Buffer.BlockCopy(data, 0, iv, 0, IvSize);
            Buffer.BlockCopy(data, IvSize, cipherText, 0, cipherText.Length);

            return (iv, cipherText);
        }

        #endregion

        #region Core Encryption/Decryption

        /// <summary>
        /// 실제 암호화를 수행하는 헬퍼 메서드
        /// </summary>
        /// <param name="plainText">암호화할 평문</param>
        /// <param name="key">암호화 키 (32바이트)</param>
        /// <param name="iv">초기화 벡터 (16바이트)</param>
        /// <param name="mode">암호화 모드</param>
        /// <param name="padding">패딩 모드</param>
        /// <returns>암호화된 바이트 배열</returns>
        public static byte[] PerformEncryption(
            string plainText,
            byte[] key,
            byte[] iv,
            CipherMode mode,
            PaddingMode padding)
        {
            using (var aes = Aes.Create())
            {
                ConfigureAes(aes, key, mode, padding);
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                    return encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
                }
            }
        }

        /// <summary>
        /// 실제 복호화를 수행하는 헬퍼 메서드
        /// </summary>
        /// <param name="encrypted">암호화된 바이트 배열</param>
        /// <param name="key">암호화 키 (32바이트)</param>
        /// <param name="iv">초기화 벡터 (16바이트)</param>
        /// <param name="mode">암호화 모드</param>
        /// <param name="padding">패딩 모드</param>
        /// <returns>복호화된 평문</returns>
        public static string PerformDecryption(
            byte[] encrypted,
            byte[] key,
            byte[] iv,
            CipherMode mode,
            PaddingMode padding)
        {
            using (var aes = Aes.Create())
            {
                ConfigureAes(aes, key, mode, padding);
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor())
                {
                    byte[] decryptedBytes = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                    return Encoding.UTF8.GetString(decryptedBytes);
                }
            }
        }

        #endregion

        #region High-Level Encrypt/Decrypt (바이트 키 직접 사용)

        /// <summary>
        /// 순수 바이트 키로 AES 암호화 (고수준 API)
        /// IV 생성 + 암호화 + 결합 + Base64 인코딩을 한번에 처리
        /// </summary>
        /// <param name="plainText">평문</param>
        /// <param name="key">32바이트 AES 키</param>
        /// <param name="mode">암호화 모드 (기본: CBC)</param>
        /// <param name="padding">패딩 모드 (기본: PKCS7)</param>
        /// <returns>Base64 인코딩된 [IV + 암호문]</returns>
        public static string EncryptWithRawKey(
            string plainText,
            byte[] key,
            CipherMode mode = CipherMode.CBC,
            PaddingMode padding = PaddingMode.PKCS7)
        {
            ValidateInput(nameof(plainText), plainText);
            ValidateKey(key);

            using (var aes = Aes.Create())
            {
                ConfigureAes(aes, key, mode, padding);
                aes.GenerateIV(); // 랜덤 IV 생성

                byte[] encrypted = PerformEncryption(plainText, key, aes.IV, mode, padding);
                byte[] result = CombineIvAndCipherText(aes.IV, encrypted);

                return Convert.ToBase64String(result);
            }
        }

        /// <summary>
        /// 순수 바이트 키로 AES 복호화 (고수준 API)
        /// Base64 디코딩 + 분리 + 복호화를 한번에 처리
        /// </summary>
        /// <param name="cipherText">Base64 인코딩된 암호문</param>
        /// <param name="key">32바이트 AES 키</param>
        /// <param name="mode">암호화 모드 (기본: CBC)</param>
        /// <param name="padding">패딩 모드 (기본: PKCS7)</param>
        /// <returns>복호화된 평문</returns>
        public static string DecryptWithRawKey(
            string cipherText,
            byte[] key,
            CipherMode mode = CipherMode.CBC,
            PaddingMode padding = PaddingMode.PKCS7)
        {
            ValidateInput(nameof(cipherText), cipherText);
            ValidateKey(key);

            byte[] data = Convert.FromBase64String(cipherText);
            var (iv, encrypted) = SeparateIvAndCipherText(data);

            return PerformDecryption(encrypted, key, iv, mode, padding);
        }

        #endregion
    }
}
