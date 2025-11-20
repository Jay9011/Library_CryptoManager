# SECUiDEACryptoManager

.NET Standard 2.0 기반의 강력하고 안전한 암호화 라이브러리입니다. AES-256, RSA-2048, SHA-512 등 다양한 암호화 알고리즘을 쉽게 사용할 수 있도록 설계되었습니다.

## 📋 목차

- [주요 기능](#-주요-기능)
- [지원 알고리즘](#-지원-알고리즘)
- [사용 방법](#-사용-방법)
  - [AES-256 암호화](#1-aes-256-암호화)
  - [SHA-512 해싱](#2-sha-512-해싱)
  - [RSA 공개키 암호화](#3-rsa-공개키-암호화)
- [인터페이스](#-인터페이스)
- [보안 특징](#-보안-특징)
- [요구 사항](#-요구-사항)

## 🎯 주요 기능

- **AES-256 대칭키 암호화**: PBKDF2 키 유도 함수를 사용한 안전한 대칭키 암호화
- **SHA-512 해싱**: 비밀번호 저장 등에 적합한 단방향 해시 함수
- **RSA-2048 비대칭 암호화**: 공개키 기반 암호화 (OAEP SHA-256 패딩)
- **Salt 지원**: 추가 보안을 위한 Salt 값 지원
- **유연한 설정**: 다양한 암호화 모드 및 패딩 모드 지원
- **.NET Standard 2.0**: 광범위한 .NET 플랫폼 호환성

## 🔐 지원 알고리즘

### AES-256 (Advanced Encryption Standard)
- **키 크기**: 256-bit
- **블록 크기**: 128-bit
- **기본 모드**: CBC (Cipher Block Chaining)
- **기본 패딩**: PKCS7
- **키 유도**: PBKDF2 (10,000회 반복)

### SHA-512 (Secure Hash Algorithm)
- **해시 크기**: 512-bit
- **용도**: 비밀번호 해싱, 데이터 무결성 검증
- **특징**: 단방향 암호화 (복호화 불가)

### RSA-2048 (Rivest-Shamir-Adleman)
- **키 크기**: 2048-bit (기본값, 사용자 설정 가능)
- **패딩**: OAEP (Optimal Asymmetric Encryption Padding) with SHA-256
- **최대 데이터 크기**: 190 바이트 (2048-bit 키 기준)
- **키 형식**: XML, PEM (.NET 5.0 이상)

## 🚀 사용 방법

### 1. AES-256 암호화

#### 기본 사용법

```csharp
using SECUiDEACryptoManager.Services;
using CryptoManager;

// 인스턴스 생성 및 키 설정
var aes = new SafetyAES256("my-secret-key");

// 암호화
string plainText = "안녕하세요, 이것은 비밀 메시지입니다.";
string encrypted = aes.Encrypt(plainText);
Console.WriteLine($"암호화: {encrypted}");

// 복호화
string decrypted = aes.Decrypt(encrypted);
Console.WriteLine($"복호화: {decrypted}");
```

#### Salt를 사용한 암호화

```csharp
var aes = new SafetyAES256("my-secret-key");

// Salt를 사용한 암호화
string plainText = "비밀 데이터";
string salt = "random-salt-value";
string encrypted = aes.Encrypt(plainText, salt);

// Salt를 사용한 복호화
string decrypted = aes.Decrypt(encrypted, salt);
```

#### 고급 설정 (암호화 모드 및 패딩 모드 커스터마이징)

```csharp
using System.Security.Cryptography;

// CBC 모드, PKCS7 패딩 (기본값)
var aes1 = new SafetyAES256("key", CipherMode.CBC, PaddingMode.PKCS7);

// ECB 모드, Zeros 패딩
var aes2 = new SafetyAES256("key", CipherMode.ECB, PaddingMode.Zeros);

// 키를 나중에 설정
var aes3 = new SafetyAES256();
aes3.SetKey("my-new-key");
```

#### 키 관리

```csharp
var aes = new SafetyAES256();

// 키가 설정되었는지 확인
if (!aes.IsKeySetted)
{
    aes.SetKey("my-secret-key");
}

// 암호화 수행
string encrypted = aes.Encrypt("데이터");
```

### 2. SHA-512 해싱

#### 기본 해싱

```csharp
using SECUiDEACryptoManager.Services;

var sha = new SafetySHA512();

// 비밀번호 해싱
string password = "user-password-123";
string hashedPassword = sha.Encrypt(password);
Console.WriteLine($"해시: {hashedPassword}");
```

#### Salt를 사용한 해싱 (권장)

```csharp
var sha = new SafetySHA512();

// Salt를 사용하면 동일한 입력값도 다른 해시를 생성
string password = "user-password-123";
string salt = Guid.NewGuid().ToString(); // 사용자마다 고유한 Salt 생성
string hashedPassword = sha.Encrypt(password, salt);

// 로그인 시 검증
string inputPassword = "user-password-123";
string verifyHash = sha.Encrypt(inputPassword, salt);
bool isValid = (hashedPassword == verifyHash);
```

#### 비밀번호 저장 예제

```csharp
// 회원가입 시
public (string hashedPassword, string salt) RegisterUser(string password)
{
    var sha = new SafetySHA512();
    string salt = Guid.NewGuid().ToString();
    string hashedPassword = sha.Encrypt(password, salt);
    
    // DB에 hashedPassword와 salt를 모두 저장
    return (hashedPassword, salt);
}

// 로그인 시
public bool VerifyPassword(string inputPassword, string storedHash, string salt)
{
    var sha = new SafetySHA512();
    string inputHash = sha.Encrypt(inputPassword, salt);
    return inputHash == storedHash;
}
```

**참고**: SHA-512는 단방향 해시 함수이므로 `Decrypt` 메서드를 호출하면 `NotSupportedException`이 발생합니다.

### 3. RSA 공개키 암호화

#### 기본 사용법 (새로운 키 쌍 생성)

```csharp
using SECUiDEACryptoManager.Services;

// 새로운 RSA 키 쌍 생성 (2048-bit)
using (var rsa = new SafetyRSA())
{
    // 공개키와 개인키 내보내기
    string publicKey = rsa.ExportPublicKey();
    string privateKey = rsa.ExportPrivateKey();
    
    // 공개키로 암호화
    string plainText = "비밀 메시지";
    string encrypted = rsa.Encrypt(plainText);
    
    // 개인키로 복호화
    string decrypted = rsa.Decrypt(encrypted);
    Console.WriteLine($"복호화: {decrypted}");
}
```

#### 기존 키로 초기화

```csharp
// 공개키만 있는 경우 (암호화만 가능)
string publicKey = "..."; // 저장된 공개키
using (var rsaEncrypt = new SafetyRSA(publicKey))
{
    string encrypted = rsaEncrypt.Encrypt("데이터");
}

// 개인키가 있는 경우 (암호화 + 복호화 가능)
string privateKey = "..."; // 저장된 개인키
using (var rsaDecrypt = new SafetyRSA(privateKey))
{
    string decrypted = rsaDecrypt.Decrypt(encrypted);
}
```

#### 키 크기 설정

```csharp
// 4096-bit RSA 키 생성 (더 높은 보안)
using (var rsa = new SafetyRSA(4096))
{
    Console.WriteLine($"키 크기: {rsa.KeySize} bit");
    Console.WriteLine($"최대 데이터 크기: {rsa.MaxDataSize} 바이트");
    
    string encrypted = rsa.Encrypt("데이터");
}
```

#### PEM 형식 지원 (.NET 5.0 이상)

```csharp
#if NET5_0_OR_GREATER
using (var rsa = new SafetyRSA())
{
    // PEM 형식으로 내보내기
    string publicKeyPEM = rsa.ExportPublicKeyPEM();
    string privateKeyPEM = rsa.ExportPrivateKeyPEM();
    
    // PEM 키 사용 가능
}
#endif
```

#### 데이터 크기 제한 처리

```csharp
using (var rsa = new SafetyRSA(2048))
{
    Console.WriteLine($"최대 암호화 가능 크기: {rsa.MaxDataSize} 바이트");
    
    string largeData = new string('A', 300); // 190바이트 초과
    
    try
    {
        string encrypted = rsa.Encrypt(largeData);
    }
    catch (ArgumentException ex)
    {
        Console.WriteLine("데이터가 너무 큽니다!");
        // 대용량 데이터는 AES + RSA 하이브리드 방식 권장
    }
}
```

## 📚 인터페이스

### ICryptoManager

모든 암호화 구현체가 구현하는 기본 인터페이스입니다.

```csharp
public interface ICryptoManager
{
    /// <summary>
    /// 암호화
    /// </summary>
    string Encrypt(string plainText);
    
    /// <summary>
    /// Salt를 사용한 암호화
    /// </summary>
    string Encrypt(string plainText, string salt);
    
    /// <summary>
    /// 복호화
    /// </summary>
    string Decrypt(string cipherText);
    
    /// <summary>
    /// Salt를 사용한 복호화
    /// </summary>
    string Decrypt(string cipherText, string salt);
}
```

### ICryptoKeyManager

암호화 키 관리 기능을 제공하는 인터페이스입니다.

```csharp
public interface ICryptoKeyManager
{
    /// <summary>
    /// 현재 암호화 키가 설정되어 있는지 여부
    /// </summary>
    bool IsKeySetted { get; }
    
    /// <summary>
    /// 암호화 키 설정
    /// </summary>
    void SetKey(string newKey);
}
```

## 🛡️ 보안 특징

### AES-256 보안
- **PBKDF2 키 유도**: 10,000회 반복으로 브루트포스 공격 방어
- **랜덤 IV**: 각 암호화마다 고유한 초기화 벡터 사용
- **SHA-256 해싱**: Salt가 없을 때 키를 정규화
- **CBC 모드**: 블록 체인 방식으로 패턴 노출 방지

### SHA-512 보안
- **512-bit 해시**: 충돌 공격에 강력한 저항성
- **Salt 지원**: 레인보우 테이블 공격 방어
- **고속 변환**: Lookup Table을 사용한 최적화된 16진수 변환

### RSA 보안
- **2048-bit 이상**: 현대 보안 표준 충족
- **OAEP SHA-256 패딩**: 선택 암호문 공격(CCA) 방어
- **키 관리**: XML 및 PEM 형식 지원으로 유연한 키 관리

## ⚙️ 요구 사항

- **.NET Standard 2.0** 이상
- 호환 가능한 플랫폼:
  - .NET Core 2.0+
  - .NET Framework 4.6.1+
  - .NET 5.0+
  - .NET 6.0+
  - .NET 7.0+
  - .NET 8.0+
  - Xamarin
  - UWP

## 🔧 고급 활용

### 의존성 주입 (Dependency Injection)

```csharp
// Startup.cs 또는 Program.cs
services.AddSingleton<ICryptoManager>(sp => 
    new SafetyAES256("your-secret-key"));

// 컨트롤러나 서비스에서 사용
public class MyService
{
    private readonly ICryptoManager _crypto;
    
    public MyService(ICryptoManager crypto)
    {
        _crypto = crypto;
    }
    
    public string EncryptData(string data)
    {
        return _crypto.Encrypt(data);
    }
}
```

### 환경 변수에서 키 로드

```csharp
// appsettings.json에서 키 가져오기
var key = Configuration["CryptoKey"];
var aes = new SafetyAES256(key);

// 환경 변수에서 키 가져오기
var key = Environment.GetEnvironmentVariable("CRYPTO_KEY");
var aes = new SafetyAES256(key);
```

## 📝 주의 사항

1. **암호화 키 보관**: 암호화 키는 안전하게 보관하세요. 키가 노출되면 모든 암호화된 데이터가 위험에 노출됩니다.

2. **RSA 데이터 크기**: RSA는 소량의 데이터 암호화에 적합합니다. 대용량 데이터는 AES를 사용하세요.

3. **Salt 관리**: Salt 값도 암호화된 데이터와 함께 저장해야 복호화가 가능합니다.

4. **SHA-512 복호화**: SHA-512는 단방향 해시 함수이므로 복호화할 수 없습니다.

5. **프로덕션 환경**: 프로덕션 환경에서는 하드코딩된 키 대신 안전한 키 관리 시스템(Azure Key Vault, AWS KMS 등)을 사용하세요.
