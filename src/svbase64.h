#include <string>
#include <iostream>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include "strongvelopetypes.h"
#include <mega/base64.h>

using namespace CryptoPP;
using CryptoPP::Name::Pad;
using CryptoPP::Name::InsertLineBreaks;

namespace Strongvelopens
{
static const std::string base64_chars =
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789-_";


static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

static std::string base64url_encode(const std::string& bytes_to_encode) {
  std::string ret;
  int i = 0;
  int j = 0;
  unsigned char char_array_3[3];
  unsigned char char_array_4[4];
  unsigned int in_len = bytes_to_encode.size();
  unsigned int index = 0;

  while (index < in_len) {
    char_array_3[i++] = (unsigned char)bytes_to_encode[index++];
    if (i == 3) {
      char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
      char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
      char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
      char_array_4[3] = char_array_3[2] & 0x3f;

      for(i = 0; (i <4) ; i++)
        ret += base64_chars[char_array_4[i]];
      i = 0;
    }
  }

  if (i)
  {
    for(j = i; j < 3; j++)
      char_array_3[j] = '\0';

    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
    char_array_4[3] = char_array_3[2] & 0x3f;

    for (j = 0; (j < i + 1); j++)
      ret += base64_chars[char_array_4[j]];

    while((i++ < 3))
      ret += '=';

  }

  return ret;

}

static inline std::string base64url_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}

static inline std::string base64_encode(const std::string& decoded)
{
	std::string toencoded;

    StringSource((byte*)decoded.data(), decoded.size(), true,
       new Base64Encoder(
           new StringSink(toencoded),
           false));
    return toencoded;
}

static inline std::string base64_decode(const std::string& encoded)
{
    std::string decoded;

    StringSource((byte*)encoded.data(), encoded.size(), true,
       new Base64Decoder(
           new StringSink(decoded)));

    return std::move(decoded);
}

static inline std::string base64u_encode(const std::string& decoded)
{
    char base64Result[decoded.size()*4/3+4];
    mega::Base64::btoa((const byte *)decoded.data(), decoded.size(), base64Result);
	return std::string(base64Result);
}

static inline std::string base64u_decode(const std::string& encoded)
{
    char bin[1024];
    int binLen = mega::Base64::atob(encoded.c_str(), (byte *)bin, sizeof(bin));
    bin[binLen] = 0;
    return std::string(bin);
}


static inline std::string base16_decode(const std::string& encoded)
{
	std::string decoded;

	HexDecoder decoder;

	decoder.Put( (byte*)encoded.data(), encoded.size() );
	decoder.MessageEnd();

	word64 size = decoder.MaxRetrievable();
	if(size && size <= SIZE_MAX)
	{
	    decoded.resize(size);
	    decoder.Get((byte*)decoded.data(), decoded.size());
	}
	return decoded;
}

static inline std::string base16_encode(const std::string& decoded)
{
	std::string encoded;

	HexEncoder encoder;

	encoder.Put( (byte*)decoded.data(), decoded.size() );
	encoder.MessageEnd();

	word64 size = encoder.MaxRetrievable();
	if(size && size <= SIZE_MAX)
	{
		encoded.resize(size);
		encoder.Get((byte*)encoded.data(), encoded.size());
	}
	return encoded;
}
}
