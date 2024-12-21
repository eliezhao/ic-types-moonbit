////////////////////////////////////////////////////////////////////////////////
// principal.mbt
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// 1. 错误类型
////////////////////////////////////////////////////////////////////////////////

type! PrincipalError {
  BytesTooLong
  InvalidBase32
  TextTooShort
  TextTooLong
  CheckSequenceNotMatch
  AbnormalGrouped(p~ : Principal)
}

////////////////////////////////////////////////////////////////////////////////
// 2. 工具函数：字符串操作
////////////////////////////////////////////////////////////////////////////////

fn char_at(s: String, i: Int) -> String {
  if i < 0 || i >= s.length() {
    ""
  } else {
    s[i].to_string()
  }
}

fn to_upper(s: String) -> String {
  let mut r = ""
  let mut i = 0
  while i < s.length() {
    let c = char_at(s, i)
    let code = c.to_char().to_int()
    // 'a'..'z' => 97..122
    if code >= 97 && code <= 122 {
      let upper_code = code - 32
      r = r + Char(upper_code).to_string()
    } else {
      r = r + c
    }
    i = i + 1
  }
  r
}

fn to_lower(s: String) -> String {
  let mut r = ""
  let mut i = 0
  while i < s.length() {
    let c = char_at(s, i)
    let code = c.to_char().to_int()
    // 'A'..'Z' => 65..90
    if code >= 65 && code <= 90 {
      let lower_code = code + 32
      r = r + Char(lower_code).to_string()
    } else {
      r = r + c
    }
    i = i + 1
  }
  r
}

fn remove_char(s: String, ch: Char) -> String {
  let mut r = ""
  let mut i = 0
  while i < s.length() {
    let c = char_at(s, i)
    if c != ch.to_string() {
      r = r + c
    }
    i = i + 1
  }
  r
}

fn string_slice(s: String, start: Int, length: Int) -> String {
  if start < 0 || length < 0 || start + length > s.length() {
    ""
  } else {
    s.slice(start, length)
  }
}

////////////////////////////////////////////////////////////////////////////////
// 3. Base32 编解码
////////////////////////////////////////////////////////////////////////////////

/// 简易 Base32 编码
fn base32_encode(data: Bytes) -> String {
  // 函数体内声明 base32_alphabet
  let base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

  let mut bits = 0
  let mut bits_len = 0
  let mut output = ""
  let mut i = 0

  while i < data.length() {
    let val = data[i].to_int() & 0xFF
    bits = (bits << 8) | val
    bits_len = bits_len + 8

    while bits_len >= 5 {
      bits_len = bits_len - 5
      let index = (bits >> bits_len) & 0x1F
      let ch = string_slice(base32_alphabet, index, 1)
      output = output + ch
    }
    i = i + 1
  }

  if bits_len > 0 {
    let index = (bits << (5 - bits_len)) & 0x1F
    let ch = string_slice(base32_alphabet, index, 1)
    output = output + ch
  }

  output
}

/// 简易 Base32 解码
fn base32_decode(s: String) -> Bytes!PrincipalError {
  // 函数体内声明 base32_alphabet
  let base32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

  let up = to_upper(s)
  let s2 = remove_char(up, '-')

  let mut bits = 0
  let mut bits_len = 0
  let mut result = Bytes::new(0)

  let mut i = 0
  while i < s2.length() {
    let c = char_at(s2, i)
    let idx = base32_find_index(c, base32_alphabet)
    if idx < 0 {
      raise InvalidBase32
    }
    bits = (bits << 5) | idx
    bits_len = bits_len + 5
    if bits_len >= 8 {
      bits_len = bits_len - 8
      let byte = (bits >> bits_len) & 0xFF
      result = result.push(byte.to_byte())
    }
    i = i + 1
  }
  result
}

/// 在 base32_alphabet 中查找字符下标
fn base32_find_index(ch: String, base32_alphabet: String) -> Int {
  let mut i = 0
  while i < base32_alphabet.length() {
    let c0 = char_at(base32_alphabet, i)
    if c0 == ch {
      return i
    }
    i = i + 1
  }
  -1
}

////////////////////////////////////////////////////////////////////////////////
// 4. Principal 结构
////////////////////////////////////////////////////////////////////////////////

struct Principal {
  bytes : Bytes
} derive(Eq)

/// 构造 management_canister
fn Principal::management_canister() -> Principal {
  { bytes: Bytes::new(0) }
}

/// 构造匿名 principal
fn Principal::anonymous() -> Principal {
  // 函数体内声明 anonymous_tag
  let anonymous_tag : Byte = 4
  let arr = Bytes::new(1)
  arr.set(0, anonymous_tag)
  { bytes: arr }
}

/// 私有构造：若 > 29 则 fail
fn principal_from_slice(data: Bytes) -> Principal!PrincipalError {
  let max_len = 29
  if data.length() > max_len {
    raise BytesTooLong
  }
  { bytes: data }
}

/// from_slice：若 >29 则 abort
fn Principal::from_slice(data: Bytes) -> Principal {
  let max_len = 29
  if data.length() > max_len {
    abort("slice length exceeds capacity")
  }
  { bytes: data }
}

fn as_slice(self: Principal) -> Bytes {
  self.bytes
}

/// from_text：只做 base32 解码 => 长度检查 => roundtrip
fn Principal::from_text(text: String) -> Principal!PrincipalError {
  let max_len = 29
  let original_lower = to_lower(text)
  let decoded = base32_decode(text)!
  if decoded.length() > max_len {
    raise TextTooLong
  }
  let p = principal_from_slice(decoded)!
  let re_encoded = p.to_text()
  if to_lower(re_encoded) != original_lower {
    raise AbnormalGrouped(p~)
  }
  p
}

/// to_text：base32 编码 + 每5字符插入 '-' + 转小写
fn to_text(self: Principal) -> String {
  let base32_str = base32_encode(self.bytes)
  let mut s = base32_str
  let mut result = ""

  while s.length() > 5 {
    let head = string_slice(s, 0, 5)
    result = result + head + "-"
    s = string_slice(s, 5, s.length() - 5)
  }
  result = result + s
  to_lower(result)
}

////////////////////////////////////////////////////////////////////////////////
// 5. 测试
////////////////////////////////////////////////////////////////////////////////

test "principal test" {
  let p = Principal::management_canister()
  assert_eq!(p.as_slice().length(), 0)

  let txt = p.to_text()
  let p2 = try {
    Principal::from_text!(txt)
  } catch {
    e => fail!("from_text failed")
  } else {
    v => v
  }
  assert_eq!(p.as_slice(), p2.as_slice())

  let anon = Principal::anonymous()
  let anon_txt = anon.to_text()
  let anon2 = try {
    Principal::from_text!(anon_txt)
  } catch {
    e => fail!("from_text failed")
  } else {
    v => v
  }
  assert_eq!(anon.as_slice(), anon2.as_slice())
}