using System;
using System.Security.Cryptography;
using System.Text;
using CryptoManager;

namespace SECUiDEACryptoManager.Services
{
    public class SafetySHA512 : ICryptoManager
    {
        private const string DefaultSeparator = "|";
        private const string DecryptNotSupportedMessage = "SHA-512는 해시 함수로 복호화를 지원하지 않습니다.";

        private static readonly string[] HexLookup = new string[256];

        static SafetySHA512()
        {
            for (int i = 0; i < 256; i++)
            {
                HexLookup[i] = i.ToString("x2");
            }
        }

        public string Encrypt(string plainText)
        {
            ValidateInput(nameof(plainText), plainText);
            return EncryptInternal(plainText, null);
        }

        public string Encrypt(string plainText, string salt)
        {
            ValidateInput(nameof(plainText), plainText);
            ValidateInput(nameof(salt), salt);
            return EncryptInternal(plainText, salt);
        }

        public string Decrypt(string cipherText)
        {
            throw new NotSupportedException(DecryptNotSupportedMessage);
        }

        public string Decrypt(string cipherText, string salt)
        {
            throw new NotSupportedException(DecryptNotSupportedMessage);
        }

        /// <summary>
        /// 입력값 검증
        /// </summary>
        /// <param name="paramName">매개변수 이름</param>
        /// <param name="value">검증할 값</param>
        /// <exception cref="ArgumentException"></exception>
        private static void ValidateInput(string paramName, string value)
        {
            if (string.IsNullOrEmpty(value))
                throw new ArgumentException($"{paramName}는 비어있을 수 없습니다.", paramName);
        }

        /// <summary>
        /// 암호화 메서드
        /// </summary>
        /// <param name="plainText">암호화할 평문</param>
        /// <param name="salt">Salt (null 가능)</param>
        /// <returns>Base64로 인코딩된 암호문</returns>
        private static string EncryptInternal(string plainText, string salt)
        {
            using (var sha512 = SHA512.Create())
            {
                byte[] inputBytes = PrepareInput(plainText, salt);
                byte[] hashBytes = sha512.ComputeHash(inputBytes);
                return BytesToHexFast(hashBytes);
            }
        }

        /// <summary>
        /// 입력값 결합
        /// </summary>
        /// <param name="input">입력 문자열</param>
        /// <param name="salt">Salt (null 가능)</param>
        /// <returns>결합된 문자열</returns>
        private static byte[] PrepareInput(string input, string salt)
        {
            string combined = string.IsNullOrEmpty(salt) ? input : $"{input}{DefaultSeparator}{salt}";
            return Encoding.UTF8.GetBytes(combined);
        }

        /// <summary>
        /// 바이트 배열을 16진수 문자열로 고속 변환 (Lookup Table 사용)
        /// </summary>
        /// <param name="bytes">변환할 바이트 배열</param>
        /// <returns>16진수 문자열 (소문자)</returns>
        private static string BytesToHexFast(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(HexLookup[bytes[i]]);
            }
            return sb.ToString();
        }
    }
}
