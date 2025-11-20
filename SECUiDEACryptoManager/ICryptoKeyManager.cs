using System;

namespace SECUiDEACryptoManager
{
    public interface ICryptoKeyManager
    {
        /// <summary>
        /// 현재 암호화 키가 설정되어 있는지 여부
        /// </summary>
        /// <returns><see cref="bool"/></returns>
        bool IsKeySetted { get; }

        /// <summary>
        /// 암호화 키 설정
        /// </summary>
        /// <param name="newKey">새로운 암호화 키</param>
        void SetKey(string newKey);
    }
}
