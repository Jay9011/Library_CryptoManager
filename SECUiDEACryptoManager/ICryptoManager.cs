namespace CryptoManager
{
    public interface ICryptoManager
    {
        /// <summary>
        /// 암호화
        /// </summary>
        /// <param name="plainText">평문</param>
        /// <returns><see cref="string"/></returns>
        /// <exception cref="InvalidCastException">전환 중 예외 발생</exception>
        string Encrypt(string plainText);

        /// <summary>
        /// Salt를 사용한 암호화
        /// </summary>
        /// <param name="plainText">평문</param>
        /// <param name="salt">솔트 값</param>
        /// <returns><see cref="string"/></returns>
        /// <exception cref="InvalidCastException">전환 중 예외 발생</exception>
        string Encrypt(string plainText, string salt);

        /// <summary>
        /// 복호화
        /// </summary>
        /// <param name="cipherText">암호문</param>
        /// <returns><see cref="string"/></returns>
        /// <exception cref="InvalidCastException">전환 중 예외 발생</exception>
        string Decrypt(string cipherText);

        /// <summary>
        /// Salt를 사용한 복호화
        /// </summary>
        /// <param name="cipherText">암호문</param>
        /// <param name="salt">솔트 값</param>
        /// <returns><see cref="string"/></returns>
        /// <exception cref="InvalidCastException">전환 중 예외 발생</exception>
        string Decrypt(string cipherText, string salt);
    }
}