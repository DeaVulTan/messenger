/*
 * main.cpp
 *
 *  Created on: 17/11/2015
 *      Author: admin2
 */
#include <iostream>
#include "../src/strongvelope.h"
#include "../src/cryptofunctions.h"
#include "../src/strongvelopetypes.h"
#include "../src/svbase64.h"
#include "../src/tlvstore.h"
#ifdef __TEST
#include "gtest/gtest.h"

#define KEY_SIZE   32

class MyUserKeyCache : public Strongvelopens::IUserKeyCache
{
protected:
	Strongvelopens::StringMapping pubCu25519;
	Strongvelopens::StringMapping pubEd25519;
public:
    virtual std::string getKey(const std::string& userhandle, Strongvelopens::KeyType keyType);
    virtual void setKey(const std::string& userhandle, const std::string& key, Strongvelopens::KeyType keyType);
    virtual bool hasUser(const std::string& userhandle) const;
};

std::string MyUserKeyCache::getKey(const std::string& userhandle, Strongvelopens::KeyType keyType)
{
	if (keyType == Strongvelopens::KeyType::PUB_ED255)
	{
		return pubEd25519[userhandle];
	}
	else if(keyType == Strongvelopens::KeyType::PUB_CU255)
	{
	    return pubCu25519[userhandle];
	}
	else
	{
	    return std::string();
	}
}

void MyUserKeyCache::setKey(const std::string& userhandle, const std::string& key, Strongvelopens::KeyType keyType)
{
	if (keyType == Strongvelopens::KeyType::PUB_ED255)
	{
		pubEd25519[userhandle] = key;
	}
	else if(keyType == Strongvelopens::KeyType::PUB_CU255)
	{
		pubCu25519[userhandle] = key;
	}
}

bool MyUserKeyCache::hasUser(const std::string& userhandle) const
{
	return true;
}

MyUserKeyCache myUserKeyCache;

std::string ED25519_PRIV_KEY = Strongvelopens::base64_decode("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=");
std::string ED25519_PUB_KEY = Strongvelopens::base64_decode("11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=");
std::string CU25519_PRIV_KEY = Strongvelopens::base64_decode("ZMB9oRI87iFj5cwKBvgzwnxxToRAO3L5P1gILfJyEik=");
std::string CU25519_PUB_KEY = Strongvelopens::base64_decode("4BXxF+5ehQKKCCR5x3hP3E0hzYry59jFTM30x9dzWRI=");
std::string TEST_KEY = Strongvelopens::base64_decode("/+fPkTwBddDWDSA2M1hluA==");
std::string TEST_NONCE = Strongvelopens::base64_decode("MTHgl79y+1FFnmnopp4UNA==");
std::string TEST_KEY_ID = Strongvelopens::base64_decode("QUkAAA==");
std::string ROTATED_KEY = Strongvelopens::base64_decode("D/1apgnOpfzZqrYi95t5pw==");
std::string ROTATED_KEY_ID = Strongvelopens::base64_decode("QUkAAQ==");
std::string ROTATION_MESSAGE_BIN = Strongvelopens::base64_decode(std::string("AAEAAEB6MqjdQi8U2RiFyLdeX6hONPNJVugKL8Jjt")
        + std::string("NBEH1+elTgItQqv+/pE6gb8zqchv59I6tMhM5e+BI45/djWY7APAgAAAQADAAAM71Br")
        + std::string("lkBJXmR5xRtMBAAACMqLuOeu/PccBQAAIIHgbD1AGIFO6HIagNL3pjHAGnKW+WwMuh2")
        + std::string("eweVCfnY6BgAACEFJAAFBSQAABwAABh+/GnXzGA=="));
std::string INITIAL_MESSAGE_BIN = Strongvelopens::base64_decode(std::string("AAEAAECuKE3arE92KkMXAdaUtbZ1riLfiLezTBFtB")
    + std::string("kZMNqNYsV402eiU2T8UN8AZPthbKkIsx7DwnhBJ2aBrvjnoF4UDAgAAAQADAAAM71B")
    + std::string("rlkBJXmR5xRtMBAAACMqLuOeu/PccBQAAEMiaxjj3mLwIOIk3mKluzXsGAAAEQUkAA")
    + std::string("AcAAAbruWm1K5g="));



std::string ED25519_PRIV_KEY_A = Strongvelopens::base64_decode("g/whh+kh2m3jBxziEhrHPL498D2mlszP322Ni4XilXg=");
std::string ED25519_PUB_KEY_A = Strongvelopens::base64_decode("0/MV7Y+GFsYGbrzZMZjAnEXVtEfb4kBgKyiX4qoCkUs=");
std::string CU25519_PRIV_KEY_A = Strongvelopens::base64_decode("dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=");
std::string CU25519_PUB_KEY_A = Strongvelopens::base64_decode("hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");

/*
std::string ED25519_PRIV_KEY_B = Strongvelopens::base64_decode("yZpwd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDM");
std::string ED25519_PUB_KEY_B = Strongvelopens::base64_decode("N-WGxrfLx_iCrILpluBxUgi2VBn3kfpD7M5i_rxLtkE");
std::string CU25519_PRIV_KEY_B = Strongvelopens::base64_decode("YRLMTVRWUldVbGRWYkdSV1lrZFNWMWxyWkZOV01XeHk");
std::string CU25519_PUB_KEY_B = Strongvelopens::base64_decode("PZG9JiESdGI0jmpypEW-paC0mgssO9QF3aabNMpIDV4");*/

std::string ED25519_PRIV_KEY_B = Strongvelopens::base64_decode("majXA7oy8tk2xdST4Ix15xy2sct5zwIz4i1igXC3/3I=");
std::string ED25519_PUB_KEY_B = Strongvelopens::base64_decode("5PFlISDnlaCTTjlqlIzyBJj+OXXoOZP3LCP2dglsAuA=");
std::string CU25519_PRIV_KEY_B = Strongvelopens::base64_decode("XasIfmJKikt54X+Lg4AO5m87sSkmGLb9HC+LJ/+I4Os=");
std::string CU25519_PUB_KEY_B = Strongvelopens::base64_decode("3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=");

/*std::string ED25519_PRIV_KEY_A = Strongvelopens::base64_decode("vtRSU1UxVXhWWGhXV0doWFYwZG9XRll3Wkc5WFJsbDM");
std::string ED25519_PUB_KEY_A = Strongvelopens::base64_decode("l99bPoOsSKRa_8y8HnFMduql9eypHk2zJyVjKzXgtP0");
std::string CU25519_PRIV_KEY_A = Strongvelopens::base64_decode("eTSTVFZGWkdXa2RYYTJSWVlUSlNXVmxVU2xOWFZteFY");
std::string CU25519_PUB_KEY_A = Strongvelopens::base64_decode("V4qin4bVZ1-QCpRkI7r7_phyMn2stk_g7Tu05s8IMBI");*/
/*
INITIAL_MESSAGE = {
    protocolVersion: 0,
    signature:  atob('rihN2qxPdipDFwHWlLW2da4i34i3s0wRbQZGTDajWLFeNNnolNk'
        + '/FDfAGT7YWypCLMew8J4QSdmga7456BeFAw=='),
    signedContent: atob('AgAAAQADAAAM71BrlkBJXmR5xRtMBAAACMqLuOeu/PccBQAA'
        + 'EMiaxjj3mLwIOIk3mKluzXsGAAAEQUkAAAcAAAbruWm1K5g='),
    type: 0x00,
    nonce: atob('71BrlkBJXmR5xRtM'),
    recipients: ['you456789xw='],
    keys: [atob('yJrGOPeYvAg4iTeYqW7New==')],
    keyIds: [KEY_ID],
    includeParticipants: [],
    excludeParticipants: [],
    payload: atob('67lptSuY')
};*/

std::string FOLLOWUP_MESSAGE_BIN = Strongvelopens::base64_decode(std::string("AAEAAECXRUab/B0G4OStZoUk3fmgbSmaKptYdbbTK")
    + std::string("Zh4GVmbB14Rn/xSR9zYypOXD7MgNRJCAFjDZ/3scsGNZTqAewgDAgAAAQEDAAAM71Br")
    + std::string("lkBJXmR5xRtMBgAABEFJAAAHAAAG67lptSuY"));
/*
FOLLOWUP_MESSAGE = {
    protocolVersion: 0,
    signature:  atob('l0VGm/wdBuDkrWaFJN35oG0pmiqbWHW20ymYeBlZmwdeEZ/8Ukfc'
        + '2MqTlw+zIDUSQgBYw2f97HLBjWU6gHsIAw=='),
    signedContent: atob('AgAAAQEDAAAM71BrlkBJXmR5xRtMBgAABEFJAAAHAAAG67lptSuY'),
    type: 0x01,
    nonce: atob('71BrlkBJXmR5xRtM'),
    recipients: [],
    keys: [],
    keyIds: [KEY_ID],
    includeParticipants: [],
    excludeParticipants: [],
    payload: atob('67lptSuY')
};*/

std::string REMINDER_MESSAGE_BIN = Strongvelopens::base64_decode(std::string("AAEAAEDct7zij9MwC0VFxLSQ+wWe+aG83Rv9NoP1V")
        + std::string("bGW/tFy9jmPxL9Y0UgvFeazKlCh9maWzjJ3rhHUj1BfQ5nq5MECAgAAAQADAAAM71Br")
        + std::string("lkBJXmR5xRtMBAAACMqLuOeu/PccBQAAEIHgbD1AGIFO6HIagNL3pjEGAAAEQUkAAQ=="));


static const unsigned char alicesk[crypto_scalarmult_BYTES]
    = { 0x49,0x32,0x54,0xFF,0x53,0x8A,0x01,0x96,0x32,0x93,0x2B,0x36,0xEB,0x40,0x1A,0x0E,0xF9,0x57,0xC8,0xBC,0x42,0x00,0xC8,0x83,0x60,0xB3,0x73,0x86,0x38,0x9B,0x94,0x94 };

static const unsigned char bobsk[crypto_scalarmult_BYTES]
    = { 0xA8,0xBD,0x7B,0x0A,0x0F,0x48,0x3D,0xC3,0x0D,0x4C,0x56,0x3A,0x4A,0x3E,0xA2,0xE7,0x5D,0xF2,0x7C,0xB2,0x79,0x3D,0x43,0x80,0x6F,0x28,0x37,0x40,0x0B,0xE3,0xDA,0x0E};

/*static const unsigned char alicepk[crypto_scalarmult_BYTES]
    = { 0xE6,0x28,0x37,0x32,0x1D,0x91,0x34,0x7A,0x0A,0xFA,0x1E,0x12,0x7E,0xF1,0xB6,0xB0,0x6D,0x4C,0xD7,0x4E,0x30,0x97,0x66,0x7B,0x81,0x82,0xCE,0x63,0xD1,0xA0,0xFF,0x49};

static const unsigned char bobpk[crypto_scalarmult_BYTES]
    = { 0xE2,0x44,0x26,0x2C,0xDE,0x9C,0x13,0x0D,0xE1,0x33,0xA5,0x01,0xB6,0x85,0x08,0xCB,0x91,0x2D,0x19,0x2C,0x09,0x44,0x87,0x75,0x5E,0x0D,0x1A,0x53,0x7D,0x81,0x14,0x2D};
*/
static char hex[crypto_scalarmult_BYTES * 2 + 1];

static const unsigned char pubed255_alice[crypto_scalarmult_BYTES]
    = { 0x96,0x48,0x56,0x2D,0x3D,0xD6,0x75,0x60,0xBC,0x31,0x84,0x8F,0x57,0xA0,0x99,0x7A,0xF9,0xB9,0x09,0x78,0x4C,0x1C,0x95,0xDD,0xB9,0x6B,0xCB,0xC6,0x92,0x0B,0x3A,0xA1 };

static const unsigned char prived255_alice[crypto_scalarmult_BYTES]
    = { 0x56,0x49,0xC6,0x90,0x47,0x34,0xAE,0x95,0xE2,0xAC,0x5C,0xA3,0x14,0xB0,0xAB,0x4E,0x56,0xA9,0x2B,0x8D,0xC8,0x4A,0x15,0x4F,0x88,0x43,0x92,0x4A,0x66,0xFD,0x6D,0x0C };

static const unsigned char alicepk[crypto_scalarmult_BYTES]
    = { 0xE6,0x28,0x37,0x32,0x1D,0x91,0x34,0x7A,0x0A,0xFA,0x1E,0x12,0x7E,0xF1,0xB6,0xB0,0x6D,0x4C,0xD7,0x4E,0x30,0x97,0x66,0x7B,0x81,0x82,0xCE,0x63,0xD1,0xA0,0xFF,0x49};

static const unsigned char bobpk[crypto_scalarmult_BYTES]
    = { 0xE2,0x44,0x26,0x2C,0xDE,0x9C,0x13,0x0D,0xE1,0x33,0xA5,0x01,0xB6,0x85,0x08,0xCB,0x91,0x2D,0x19,0x2C,0x09,0x44,0x87,0x75,0x5E,0x0D,0x1A,0x53,0x7D,0x81,0x14,0x2D};


Strongvelopens::Strongvelope::ProtocolHandler* _makeParticipant(const std::string& handle)
{
	unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	unsigned char ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	unsigned char curve25519_pk[crypto_scalarmult_curve25519_BYTES];
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_keypair(ed25519_pk, ed25519_sk);

	crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk);
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk);

	std::string ed_pk_str = std::string((char*)ed25519_pk);
	std::string ed_sk_str = std::string((char*)ed25519_sk);

	std::string cu_pk_str = std::string((char*)curve25519_pk);
	std::string cu_sk_str = std::string((char*)curve25519_sk);

	myUserKeyCache.setKey(handle, cu_pk_str, Strongvelopens::KeyType::PUB_CU255);
	myUserKeyCache.setKey(handle, ed_pk_str, Strongvelopens::KeyType::PUB_ED255);
    Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(handle, cu_sk_str, ed_sk_str, ed_pk_str, myUserKeyCache);

    p->setMyPubCu25519(cu_pk_str);

    return p;
}
TEST(CRYPTO_TEST, crypto_scalarmult)
{
    std::string alicesk_str = std::string((char*)alicesk, crypto_scalarmult_BYTES);
    std::string bobsk_str = std::string((char*)bobsk, crypto_scalarmult_BYTES);

    //unsigned char alicepk [crypto_scalarmult_BYTES];
    //unsigned char bobpk [crypto_scalarmult_BYTES];
    unsigned char k[crypto_scalarmult_BYTES];
    unsigned char k1[crypto_scalarmult_BYTES];
    unsigned char k2[crypto_scalarmult_BYTES];
    int ret;

    assert(alicepk != NULL && bobpk != NULL && k != NULL);

    /*crypto_scalarmult_base(alicepk, Strongvelopens::ustring(alicesk_str));
    std::string alicepk_str = std::string((char*)alicepk, crypto_scalarmult_BYTES);
    std::cout<<Strongvelopens::base64_encode(alicepk_str)<<std::endl;
    sodium_bin2hex(hex, sizeof hex, alicepk, crypto_scalarmult_BYTES);*/


    /*crypto_scalarmult_base(bobpk, Strongvelopens::ustring(bobsk_str));
    sodium_bin2hex(hex, sizeof hex, bobpk, crypto_scalarmult_BYTES);
    std::string bobpk_str = std::string((char*)bobpk, crypto_scalarmult_BYTES);
    std::cout<<Strongvelopens::base64_encode(bobpk_str)<<std::endl;*/


    ret = crypto_scalarmult(k1, Strongvelopens::ustring(alicesk_str), bobpk);
    std::string k1_str = std::string((char*)k1, crypto_scalarmult_BYTES);
    assert(ret == 0);
    sodium_bin2hex(hex, sizeof hex, k, crypto_scalarmult_BYTES);
    std::cout<<Strongvelopens::base64_encode(k1_str)<<std::endl;

    ret = crypto_scalarmult(k2, bobsk, alicepk);
    std::string k2_str = std::string((char*)k2, crypto_scalarmult_BYTES);
    assert(ret == 0);
    sodium_bin2hex(hex, sizeof hex, k, crypto_scalarmult_BYTES);
    std::cout<<Strongvelopens::base64_encode(k2_str)<<std::endl;
    for (int i=0;i<crypto_scalarmult_BYTES;i++)
    EXPECT_EQ(k1[i], k2[i]);
}

TEST(RSA_TEST, CanEncrypt)
{
    std::vector<std::string> RSA_PUB_KEY;
    RSA_PUB_KEY.push_back(Strongvelopens::base64_decode(std::string("wT+JSBnBNjgalMGT5hmFHd/N5eyncAA+w1TzFC4PYfB")
            + std::string("nbX1CFcx6E7BuB0SqgxbJw3ZsvvowsjRvuo8SNtfmVIz4fZV45pBPxCkeCWonN/")
            + std::string("zZZiT3LnYnk1BfnfxfoXtEYRrdVPXAC/VDc9cgy29OXKuuNsREKznb9JFYQUVH9")
            + std::string("FM=")));
    RSA_PUB_KEY.push_back(Strongvelopens::base64_decode(std::string("AQAB")));

    std::vector<std::string> RSA_PRIV_KEY;
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("wT+JSBnBNjgalMGT5hmFHd/N5eyncAA+w1TzFC4PYfB")
            + std::string("nbX1CFcx6E7BuB0SqgxbJw3ZsvvowsjRvuo8SNtfmVIz4fZV45pBPxCkeCWonN/")
            + std::string("zZZiT3LnYnk1BfnfxfoXtEYRrdVPXAC/VDc9cgy29OXKuuNsREKznb9JFYQUVH9")
            + std::string("FM=")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("AQAB")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("B1SXqop/j8T1DSuCprnVGNsCfnRJra/0sYgpaFyO7NI")
            + std::string("nujmEJjuJbfHFWrU6GprksGtvmJb4/emLS3Jd6IKsE/wRthTLLMgbzGm5rRZ92g")
            + std::string("k8XGY3dUrNDsnphFsbIkTVl8n2PX6gdr2hn+rc2zvRupAYkV/smBZX+3pDAcuHo")
            + std::string("+E=")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("7y+NkdfNlnENazteobZ2K0IU7+Mp59BgmrhBl0TvhiA")
            + std::string("5HkI9WJDIZK67NsDa9QNdJ/NCfmqE/eNkZqFLVq0c+w==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("ztVHfgrLnINsPFTjMmjgZM6M39QEUsi4erg4s2tJiuI")
            + std::string("v29szH1n2HdPKFRIUPnemj48kANvp5XagAAhOb8u2iQ==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("IniC+aLVUTonye17fOjT7PYQGGZvsqX4VjP51/gqYPU")
            + std::string("h5jd7qdjr2H7KImD27Vq3wTswuRFW61QrMxNJzUsTow==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("TeoqNGD8sskPTOrta1/2qALnLqo/tq/GTvR255/S5G6")
            + std::string("weLHqYDUTcckGp0lYNu/73ridZ3VwdvBo9ZorchHbgQ==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("JhqTYTqT5Dj6YoWHWNHbOz24NmMZUXwDms/MDOBM0Nc")
            + std::string("0nX6NjLDooFrJZtBMGMgcSQJd4rULuH94+szNGc2GAg==")));

    std::string plaintext("Hello, World");
    std::string rsa = Strongvelopens::rsaEncryptString(plaintext, RSA_PUB_KEY);
    std::string decryptedtext = Strongvelopens::rsaDecryptString(rsa, RSA_PRIV_KEY);

    EXPECT_EQ(plaintext, decryptedtext);
}

TEST(AES_CTR_TEST, CanEncrypt)
{
  std::string key = Strongvelopens::base16_decode(std::string("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
  std::string nonce = Strongvelopens::base16_decode(std::string("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  std::string message = Strongvelopens::base16_decode(std::string("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"));
  std::string ecrypted = Strongvelopens::base16_decode(std::string("601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c52b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6"));

  std::string encryptedMsg = Strongvelopens::aesCTREncrypt(message, key, nonce);

  EXPECT_EQ(ecrypted, encryptedMsg);
}

TEST(AES_CTR_TEST, CanDecrypt)
{
  std::string key = Strongvelopens::base16_decode(std::string("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
  std::string nonce = Strongvelopens::base16_decode(std::string("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
  std::string message = Strongvelopens::base16_decode(std::string("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"));

  std::string encryptedMsg = Strongvelopens::aesCTREncrypt(message, key, nonce);
  std::string decryptedMsg = Strongvelopens::aesCTRDecrypt(encryptedMsg, key, nonce);

  EXPECT_EQ(message, decryptedMsg);
}


TEST(STRONGVELOPE_TEST, _symmetricEncryptMessage)
{
	std::string msg("forty two");
	std::string expected("J+79wd1gGVjQ");
	auto result = Strongvelopens::Strongvelope::_symmetricEncryptMessage(msg, TEST_KEY, TEST_NONCE);
	std::string encodedEncryptedMessage = Strongvelopens::base64_encode(result.ciphertext);

	//std::cout<<encodedEncryptedMessage<<std::endl;
    EXPECT_EQ(encodedEncryptedMessage, expected);
    EXPECT_EQ(Strongvelopens::base64_encode(result.key), Strongvelopens::base64_encode(TEST_KEY));
    EXPECT_EQ(Strongvelopens::base64_encode(result.nonce), Strongvelopens::base64_encode(TEST_NONCE));
}

TEST(STRONGVELOPE_TEST, _symmetricDecryptMessage)
{
	std::string msg("forty two");
	auto result = Strongvelopens::Strongvelope::_symmetricEncryptMessage(msg, TEST_KEY, TEST_NONCE);
	auto clearStr = Strongvelopens::Strongvelope::_symmetricDecryptMessage(result.ciphertext, TEST_KEY, TEST_NONCE);

    EXPECT_EQ(clearStr, msg);
}

TEST(STRONGVELOPE_TEST, _symmetricDecryptEmptyMessage)
{
	std::string msg;
	auto clearStr = Strongvelopens::Strongvelope::_symmetricDecryptMessage(msg, TEST_KEY, TEST_NONCE);

    EXPECT_EQ(clearStr, msg);
}

TEST(STRONGVELOPE_TEST, emptyMasterNonce)
{
    std::string empty;
    std::string expected("+BqVrzgYecM/lkxYn6CW+hM6B2BumXblRwYOeg6g9fM=");
    std::string mNonce = Strongvelopens::Strongvelope::deriveNonceSecret(empty);
    std::string result = Strongvelopens::base64_encode(mNonce);

    EXPECT_EQ(expected, result);
}

TEST(STRONGVELOPE_TEST, _signMessage)
{
	std::string msg("forty two");
	std::string result = Strongvelopens::Strongvelope::_signMessage(msg, ED25519_PRIV_KEY, ED25519_PUB_KEY);
	auto encodedStr = Strongvelopens::base64_encode(result);

	std::string expectedCode("WlGvF9zODTQOA+lTrb2jRe8bCz7Azhh2/9hze54SPWJpbfZ41SUZswe3b8KjpO0o3id9FVpNFI63ToXjw+iRCQ==");
    EXPECT_EQ(encodedStr, expectedCode);
}

TEST(STRONGVELOPE_TEST, _verifyMessage)
{
	std::string msg("forty two");
	std::string key1("WlGvF9zODTQOA+lTrb2jRe8bCz7Azhh2/9hze54S");
	std::string key2("PWJpbfZ41SUZswe3b8KjpO0o3id9FVpNFI63ToXjw+iRCQ==");
    std::string signature = Strongvelopens::base64_decode(key1 + key2);
    auto result = Strongvelopens::Strongvelope::_verifyMessage(msg, signature, ED25519_PUB_KEY);

    EXPECT_EQ(result, true);
}



TEST(STRONGVELOPE_PROTOCOL_TEST, _computeSymmetricKey_NoKey)
{
	std::string handle("me3456789xw");
	std::string yourkey("you456789xw");
    std::string expectedResult("vb4//1yAvz0AHQnUUrrL0mcNr4xN9rRu7+6YMFQQf6U=");

	Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(handle, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);

	ASSERT_DEATH( p->_computeSymmetricKey(yourkey), "");
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _encryptKeysFor_ONEKEY)
{
	std::string handle("me3456789xw");
	std::string yourkey("you456789xw");
    std::string expectedResult("q+J3tvgw2uJ3dFSZcQPWlQ==");

	Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(handle, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);
	myUserKeyCache.setKey(yourkey, CU25519_PUB_KEY, Strongvelopens::KeyType::PUB_CU255);
	Strongvelopens::StringArray keys;
	keys.push_back(TEST_KEY);
	auto result = p->_encryptKeysFor(keys, TEST_NONCE, yourkey);
	std::string encodedKey = Strongvelopens::base64_encode(result);
	delete p;
	EXPECT_EQ(encodedKey, expectedResult);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _encryptKeysFor_TWOKEYS)
{
	std::string handle("me3456789xw");
	std::string yourkey("you456789xw");
    std::string expectedResult("blbCHX3bmuYQAJAb8EyPu14vGR27oDrOrJ1CIhmVrY0=");
	myUserKeyCache.setKey(yourkey, CU25519_PUB_KEY, Strongvelopens::KeyType::PUB_CU255);

	Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(handle, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);

	Strongvelopens::StringArray keys;
	keys.push_back(ROTATED_KEY);
	keys.push_back(TEST_KEY);
	auto result = p->_encryptKeysFor(keys, TEST_NONCE, yourkey);
	std::string encodedKey = Strongvelopens::base64_encode(result);
	delete p;
	EXPECT_EQ(encodedKey, expectedResult);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _decryptKeysFor_ONEKEY)
{
    std::string handle("me3456789xw");
    std::string yourkey("you456789xw");
    Strongvelopens::StringArray expectedResult;
    expectedResult.push_back(TEST_KEY);
	myUserKeyCache.setKey(yourkey, CU25519_PUB_KEY, Strongvelopens::KeyType::PUB_CU255);
	myUserKeyCache.setKey(handle, CU25519_PUB_KEY, Strongvelopens::KeyType::PUB_CU255);

    Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(yourkey, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);

    std::string key = Strongvelopens::base64_decode("q+J3tvgw2uJ3dFSZcQPWlQ==");
    auto result = p->_decryptKeysFor(key, TEST_NONCE, handle);
    delete p;

    EXPECT_EQ(result, expectedResult);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _decryptKeysFor_MYSELF)
{
    std::string handle("me3456789xw");
    std::string yourkey("you456789xw");
    Strongvelopens::StringArray expectedResult;
    expectedResult.push_back(TEST_KEY);
    myUserKeyCache.setKey(yourkey, CU25519_PUB_KEY, Strongvelopens::KeyType::PUB_CU255);
    Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(handle, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);

    std::string key = Strongvelopens::base64_decode("q+J3tvgw2uJ3dFSZcQPWlQ==");
    auto result = p->_decryptKeysFor(key, TEST_NONCE, yourkey, true);
    delete p;

    EXPECT_EQ(result, expectedResult);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _decryptKeysFor_TWOKEYS)
{
    std::string handle("me3456789xw");
    std::string yourkey("you456789xw");
    Strongvelopens::StringArray expectedResult;
    expectedResult.push_back(ROTATED_KEY);
    expectedResult.push_back(TEST_KEY);
	myUserKeyCache.setKey(yourkey, CU25519_PUB_KEY, Strongvelopens::KeyType::PUB_CU255);
	myUserKeyCache.setKey(handle, CU25519_PUB_KEY, Strongvelopens::KeyType::PUB_CU255);

    Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(yourkey, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);
    std::string key = Strongvelopens::base64_decode("blbCHX3bmuYQAJAb8EyPu14vGR27oDrOrJ1CIhmVrY0=");
    auto result = p->_decryptKeysFor(key, TEST_NONCE, handle);
    delete p;

    EXPECT_EQ(result, expectedResult);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _parseMessageContent_INITIALMESSAGE)
{
    std::string yourkey("you456789xw");
	Strongvelopens::Strongvelope::ParsedContent expectedContent;
	expectedContent.protocolVersion = 0x00;
	expectedContent.signedContent = Strongvelopens::base64_decode(std::string("AgAAAQADAAAM71BrlkBJXmR5xRtMBAAACMqLuOeu/PccBQAA")
            + std::string("EMiaxjj3mLwIOIk3mKluzXsGAAAEQUkAAAcAAAbruWm1K5g="));
	expectedContent[Strongvelopens::TLV_TYPES::RECIPIENT].push_back("you456789xw");
	expectedContent[Strongvelopens::TLV_TYPES::KEYS].push_back(Strongvelopens::base64_decode("yJrGOPeYvAg4iTeYqW7New=="));
	expectedContent[Strongvelopens::TLV_TYPES::PAYLOAD].push_back(Strongvelopens::base64_decode("67lptSuY"));

    Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(yourkey, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);
    Strongvelopens::Strongvelope::ParsedContent parsedContent;
    Strongvelopens::Strongvelope::_parseMessageContent(INITIAL_MESSAGE_BIN, parsedContent);
    delete p;

    EXPECT_EQ(parsedContent.signedContent, expectedContent.signedContent);
    EXPECT_EQ(parsedContent.protocolVersion, expectedContent.protocolVersion);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::RECIPIENT][0], expectedContent[Strongvelopens::TLV_TYPES::RECIPIENT][0]);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::KEYS][0], expectedContent[Strongvelopens::TLV_TYPES::KEYS][0]);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::PAYLOAD][0], expectedContent[Strongvelopens::TLV_TYPES::PAYLOAD][0]);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _parseMessageContent_FOLLOWUPMESSAGE)
{
    std::string yourkey("you456789xw");
	Strongvelopens::Strongvelope::ParsedContent expectedContent;
	expectedContent.protocolVersion = 0x00;
	expectedContent.signedContent = Strongvelopens::base64_decode(std::string("AgAAAQEDAAAM71BrlkBJXmR5xRtMBgAABEFJAAAHAAAG67lptSuY"));
	expectedContent[Strongvelopens::TLV_TYPES::SIGNATURE].push_back(Strongvelopens::base64_decode( std::string("l0VGm/wdBuDkrWaFJN35oG0pmiqbWHW20ymYeBlZmwdeEZ/8Ukfc") + std::string("2MqTlw+zIDUSQgBYw2f97HLBjWU6gHsIAw==")));
	expectedContent[Strongvelopens::TLV_TYPES::PAYLOAD].push_back(Strongvelopens::base64_decode("67lptSuY"));

    Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(yourkey, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);
    Strongvelopens::Strongvelope::ParsedContent parsedContent;
    Strongvelopens::Strongvelope::_parseMessageContent(FOLLOWUP_MESSAGE_BIN, parsedContent);
    delete p;

    EXPECT_EQ(parsedContent.signedContent, expectedContent.signedContent);
    EXPECT_EQ(parsedContent.protocolVersion, expectedContent.protocolVersion);
    EXPECT_EQ(parsedContent.messageType, Strongvelopens::MESSAGE_TYPES::GROUP_FOLLOWUP);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::PAYLOAD][0], expectedContent[Strongvelopens::TLV_TYPES::PAYLOAD][0]);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::SIGNATURE][0], expectedContent[Strongvelopens::TLV_TYPES::SIGNATURE][0]);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _parseMessageContent_REMINDERMESSAGE)
{
    std::string yourkey("you456789xw");
	Strongvelopens::Strongvelope::ParsedContent expectedContent;
	expectedContent.protocolVersion = 0x00;
	expectedContent.signedContent = Strongvelopens::base64_decode(std::string("AgAAAQADAAAM71BrlkBJXmR5xRtMBAAACMqLuOeu/PccBQAAEI") + std::string("AgAAAQADAAAM71BrlkBJXmR5xRtMBAAACMqLuOeu/PccBQAAEIAgAAAQADAAAM71BrlkBJXmR5xRtMBAAACMqLuOeu/PccBQAAEI"));
	expectedContent[Strongvelopens::TLV_TYPES::SIGNATURE].push_back(Strongvelopens::base64_decode( std::string("3Le84o/TMAtFRcS0kPsFnvmhvN0b/TaD9VWxlv7RcvY5j8S/WNFIL") + std::string("xXmsypQofZmls4yd64R1I9QX0OZ6uTBAg==")));
	expectedContent[Strongvelopens::TLV_TYPES::NONCE].push_back(Strongvelopens::base64_decode("71BrlkBJXmR5xRtM"));
	expectedContent[Strongvelopens::TLV_TYPES::KEYS].push_back(Strongvelopens::base64_decode("geBsPUAYgU7ochqA0vemMQ=="));
	expectedContent[Strongvelopens::TLV_TYPES::RECIPIENT].push_back("you456789xw");

    Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(yourkey, CU25519_PRIV_KEY, ED25519_PRIV_KEY, ED25519_PUB_KEY, myUserKeyCache);
    Strongvelopens::Strongvelope::ParsedContent parsedContent;
    Strongvelopens::Strongvelope::_parseMessageContent(REMINDER_MESSAGE_BIN, parsedContent);
    delete p;

    //EXPECT_EQ(parsedContent.signedContent, expectedContent.signedContent);
    EXPECT_EQ(parsedContent.protocolVersion, expectedContent.protocolVersion);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::RECIPIENT][0], expectedContent[Strongvelopens::TLV_TYPES::RECIPIENT][0]);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::NONCE][0], expectedContent[Strongvelopens::TLV_TYPES::NONCE][0]);
    EXPECT_EQ(parsedContent[Strongvelopens::TLV_TYPES::SIGNATURE][0], expectedContent[Strongvelopens::TLV_TYPES::SIGNATURE][0]);
}

TEST(TLVSTORE_TEST, toTlvRecord)
{
    std::string key("foo");
    std::string value("bar");
    std::string expected("foo");
    expected += ((char)0);
    expected += ((char)0);
    expected += ((char)3);
    expected += value;

    std::string result = Strongvelopens::TLVStore::toTlvRecord(key, value);
    EXPECT_EQ(result, expected);
}

TEST(TLVSTORE_TEST,  splitSingleTlvRecord)
{
    std::string tests("foo");
    tests += (char)0;
    tests += (char)0;
    tests += (char)3;
    tests += "bar";
    tests += "puEd255";
    tests += (char)0;
    tests += (char)0;
    tests += (char)0x20;
    tests += ED25519_PUB_KEY;

    Strongvelopens::TLVStorevalue value;
    auto rest = Strongvelopens::TLVStore::splitSingleTlvRecord(tests, value);
    EXPECT_EQ(value.first, "foo");
    EXPECT_EQ(value.second, "bar");

    rest = Strongvelopens::TLVStore::splitSingleTlvRecord(rest, value);
    EXPECT_EQ(value.first, "puEd255");
    EXPECT_EQ(value.second, ED25519_PUB_KEY);
}

TEST(SET_TEST,  contructor)
{
    std::vector<std::string> tests;
    tests.push_back("");
    tests.push_back("Don't panic!");
    tests.push_back("Flying Spaghetti Monster");
    tests.push_back("Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn");
    tests.push_back("Tēnā koe");
    tests.push_back("Hänsel & Gretel");
    tests.push_back("Слартибартфаст");

    Strongvelopens::Set<std::string> s;

    s.fromArray(tests);
    /*for(int i=0;i< s.size();i++)
    {
    	std::cout<<s[i]<<std::endl;
    }*/
    EXPECT_EQ(s.size(), tests.size());
    EXPECT_EQ(true, s.has(tests[4]));
    EXPECT_EQ(false, s.has("mytest"));
}

TEST(SET_TEST,  join)
{
    std::vector<std::string> tests;
    tests.push_back("1");
    tests.push_back("2");
    tests.push_back("3");
    tests.push_back("5");
    tests.push_back("7");
    tests.push_back("9");
    tests.push_back("a");

    Strongvelopens::Set<std::string> s1;

    s1.fromArray(tests);

    Strongvelopens::Set<std::string> s2;
    s2.add("2");
    s2.add("3");
    s2.add("4");

    Strongvelopens::Set<std::string> s3 = s2.join(s1);
    EXPECT_EQ(true, s3.has(tests[0]));
    EXPECT_EQ(true, s3.has(tests[3]));
    EXPECT_EQ(true, s3.has(tests[4]));
    EXPECT_EQ(true, s3.has(tests[5]));
}

TEST(SET_TEST,  subtract)
{
    std::vector<std::string> tests;
    tests.push_back("1");
    tests.push_back("2");
    tests.push_back("3");
    tests.push_back("5");
    tests.push_back("7");
    tests.push_back("9");
    tests.push_back("a");

    Strongvelopens::Set<std::string> s1;

    s1.fromArray(tests);

    Strongvelopens::Set<std::string> s2;
    s2.add("2");
    s2.add("3");
    s2.add("4");

    Strongvelopens::Set<std::string> s3 = s1.subtract(s2);
    Strongvelopens::Set<std::string> s4 = s2.subtract(s1);
    EXPECT_EQ(true, s3.has(tests[0]));
    EXPECT_EQ(false, s3.has(tests[1]));
    EXPECT_EQ(false, s3.has(tests[2]));
    EXPECT_EQ(true, s4.has(s2[2]));
    EXPECT_EQ(false, s4.has(s2[1]));
}

TEST(SET_TEST,  remove)
{
    std::vector<std::string> tests;
    tests.push_back("1");
    tests.push_back("2");
    tests.push_back("3");
    tests.push_back("5");
    tests.push_back("7");
    tests.push_back("9");
    tests.push_back("a");

    Strongvelopens::Set<std::string> s1;

    s1.fromArray(tests);

    EXPECT_EQ(true, s1.has(tests[0]));
    s1.remove(tests[0]);
    EXPECT_EQ(false, s1.has(tests[0]));
    s1.add(tests[0]);
    EXPECT_EQ(true, s1.has(tests[0]));
}

TEST(STRONGVELOPE_PROTOCOL_TEST, _encryptKeysFor__decryptKeysFor)
{
	std::string handle("me3456789xw");
	std::string yourkey("you456789xw");

    Strongvelopens::StringArray expectedResult;
    expectedResult.push_back(TEST_KEY);
    myUserKeyCache.setKey(yourkey, CU25519_PUB_KEY_B, Strongvelopens::KeyType::PUB_CU255);
    myUserKeyCache.setKey(yourkey, ED25519_PUB_KEY_B, Strongvelopens::KeyType::PUB_ED255);
    myUserKeyCache.setKey(handle, CU25519_PUB_KEY_A, Strongvelopens::KeyType::PUB_CU255);
    myUserKeyCache.setKey(handle, ED25519_PUB_KEY_A, Strongvelopens::KeyType::PUB_ED255);

	Strongvelopens::Strongvelope::ProtocolHandler * p = new Strongvelopens::Strongvelope::ProtocolHandler(handle, CU25519_PRIV_KEY_A, ED25519_PRIV_KEY_A, ED25519_PUB_KEY_A, myUserKeyCache);
	p->addParticipant(yourkey);
	Strongvelopens::Strongvelope::ProtocolHandler * q = new Strongvelopens::Strongvelope::ProtocolHandler(yourkey, CU25519_PRIV_KEY_B, ED25519_PRIV_KEY_B, ED25519_PUB_KEY_B, myUserKeyCache);

	Strongvelopens::StringArray keys;
	keys.push_back(TEST_KEY);
	auto result = p->_encryptKeysFor(keys, TEST_NONCE, yourkey);
	auto decrypted = q->_decryptKeysFor(result, TEST_NONCE, handle);

    EXPECT_EQ(decrypted, expectedResult);
}

TEST(STRONGVELOPE_PROTOCOL_TEST, one_on_one_chat)
{
    std::vector<std::string> tests;
    tests.push_back("");
    tests.push_back("Don't panic!");
    tests.push_back("Flying Spaghetti Monster");
    tests.push_back("Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn");
    tests.push_back("Tēnā koe");
    tests.push_back("Hänsel & Gretel");
    tests.push_back("Слартибартфаст");

    std::string aName("alice678900");
    std::string bName("bob45678900");

    auto alice = _makeParticipant(aName);
    //alice->rotateKeyEvery = 5;
    //alice->totalMessagesBeforeSendKey = 10;
    alice->addParticipant(bName);
    alice->updateSenderKey();
    std::string sent;
    std::string message;

    auto bob = _makeParticipant(bName);
    //bob->rotateKeyEvery = 10;
    //bob->totalMessagesBeforeSendKey = 5;
    bob->addParticipant(aName);
    bob->updateSenderKey();

    int messagesProcessedAlice = 0;
    for (int i = 0; i<tests.size();i++)
    {
    	message = tests[i];
    	messagesProcessedAlice++;
        sent = alice->encryptTo(message, bName);

        Strongvelopens::StrongvelopeMessage* parsedContent;
        //std::cout << "Alice encrypts a message to send to Bob."<<message<<std::endl;
        parsedContent = alice->decryptFrom(sent, aName);
        if (parsedContent)
        {
        	EXPECT_EQ(message, parsedContent->payload);
        }
        else
        {
        	std::cout<<"Alice can not decrypt her own message:"<<std::endl;
        }
        Strongvelopens::StrongvelopeMessage* BobParsedContent;

        BobParsedContent = bob->decryptFrom(sent, aName);
        if (BobParsedContent)
        {
        	EXPECT_EQ(message, BobParsedContent->payload);
        }
        // Bob echoes it.
        sent = bob->encryptTo(BobParsedContent->payload, aName);

        // Bob receives his own message.
        Strongvelopens::StrongvelopeMessage* BobParsedContent2;
        BobParsedContent2 = bob->decryptFrom(sent, bName);
        if (BobParsedContent2)
        {
        EXPECT_EQ(message, BobParsedContent2->payload);
        }
        else
        {
        	std::cerr<<"can't decrypt message"<<std::endl;
        }

        // Alice gets it back.
        Strongvelopens::StrongvelopeMessage* AliceParsedContent;
        AliceParsedContent = alice->decryptFrom(sent, bName);
        EXPECT_EQ(message, AliceParsedContent->payload);
        delete parsedContent;
        delete BobParsedContent;
        delete BobParsedContent2;
        delete AliceParsedContent;
    }
}

TEST(STRONGVELOPE_PROTOCOL_TEST, one_on_one_chat_2)
{
    std::vector<std::string> tests;
    tests.push_back("");
    tests.push_back("Don't panic!");
    tests.push_back("Flying Spaghetti Monster");
    tests.push_back("Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn");
    tests.push_back("Tēnā koe");
    tests.push_back("Hänsel & Gretel");
    tests.push_back("Слартибартфаст");

    std::string aName("rJIQ1EpqAlA");
    std::string bName("CUGL79iRArc");
    //std::string aName("alice678900");
    //std::string bName("bob45678900");
    myUserKeyCache.setKey(aName, CU25519_PUB_KEY_A, Strongvelopens::KeyType::PUB_CU255);
    myUserKeyCache.setKey(aName, ED25519_PUB_KEY_A, Strongvelopens::KeyType::PUB_ED255);
    myUserKeyCache.setKey(bName, CU25519_PUB_KEY_B, Strongvelopens::KeyType::PUB_CU255);
    myUserKeyCache.setKey(bName, ED25519_PUB_KEY_B, Strongvelopens::KeyType::PUB_ED255);

    auto alice = new Strongvelopens::Strongvelope::ProtocolHandler(aName, CU25519_PRIV_KEY_A, ED25519_PRIV_KEY_A, ED25519_PUB_KEY_A, myUserKeyCache);
    alice->setMyPubCu25519(CU25519_PUB_KEY_A);
    auto bob = new Strongvelopens::Strongvelope::ProtocolHandler(bName, CU25519_PRIV_KEY_B, ED25519_PRIV_KEY_B, ED25519_PUB_KEY_B, myUserKeyCache);
    bob->setMyPubCu25519(CU25519_PUB_KEY_B);

    //alice->rotateKeyEvery = 5;
    //alice->totalMessagesBeforeSendKey = 10;
    alice->addParticipant(bName);
    alice->updateSenderKey();

    //bob->rotateKeyEvery = 10;
    //bob->totalMessagesBeforeSendKey = 5;
    bob->addParticipant(aName);
    //bob->updateSenderKey();

    std::string sent;
    std::string message;
    int messagesProcessedAlice = 0;
    for (int i = 0; i<tests.size();i++)
    {
        message = tests[i];
        messagesProcessedAlice++;
        sent = alice->encryptTo(message, bName);


        Strongvelopens::StrongvelopeMessage* parsedContent;
        //std::cout << "Alice encrypts a message to send to Bob."<<message<<std::endl;
        parsedContent = alice->decryptFrom(sent, aName);
        if (parsedContent)
        {
            std::cout<<"decryptd:"<<parsedContent->payload<<std::endl;
            EXPECT_EQ(message, parsedContent->payload);
        }
        else
        {
            std::cout<<"Alice can not decrypt her own message:"<<std::endl;
        }
        Strongvelopens::StrongvelopeMessage* BobParsedContent = NULL;

        BobParsedContent = bob->decryptFrom(sent, aName);
        if (BobParsedContent)
        {
         	EXPECT_EQ(message, BobParsedContent->payload);
        }
    }
}

static std::vector<Strongvelopens::ChatMessage> _messageBuffer;

static void _checkReceivers(const std::string& sent, const std::string& sender,  const std::string& message, std::map<std::string, Strongvelopens::Strongvelope::ProtocolHandler*>& participants, Strongvelopens::StringSet& activeParticipants)
{
	_messageBuffer.push_back(Strongvelopens::ChatMessage(sender, sent,Strongvelopens::Strongvelope::_dateStampNow()));
	for(std::map<std::string, Strongvelopens::Strongvelope::ProtocolHandler*>::iterator it = participants.begin();
			it != participants.end();
			it++)
	{
		Strongvelopens::StrongvelopeMessage* received;
		Strongvelopens::Strongvelope::ProtocolHandler* person = it->second;
		received = person->decryptFrom(sent, sender);
        if (received && activeParticipants.has(person->getOwnHandle()))
        {
        	std::cout<<"Decrypted:"<<received->payload<<std::endl;
        	if (!message.empty())
        	EXPECT_EQ(received->payload, message);
            if (sender != person->getOwnHandle())
            {
            	EXPECT_EQ(true, person->hasParticipant(sender));
            }
            delete received;
        }
	}
}

TEST(STRONGVELOPE_PROTOCOL_TEST, group_chat_with_chatkeys)
{
	_messageBuffer.clear();
	std::map<std::string, Strongvelopens::Strongvelope::ProtocolHandler*> participants;
	Strongvelopens::StringSet activeParticipants;

    std::string handle("me3456789xw");
    std::string yourkey("you456789xw");
    std::string otherkey("other6789xw");
    std::string keyId("AI");
    std::string preKeyId("AI");

    keyId += (char)0;
    keyId += (char)0;
    preKeyId += (char)0;
    preKeyId += (char)1;
    /*
     * ['', '42', "Don't panic!", 'Flying Spaghetti Monster',
                         "Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn",
                         'Tēnā koe', 'Hänsel & Gretel', 'Слартибартфаст'];
     */
    std::vector<std::string> tests;
    tests.push_back("");
    tests.push_back("Don't panic!");
    tests.push_back("Flying Spaghetti Monster");
    tests.push_back("Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn");
    tests.push_back("Tēnā koe");
    tests.push_back("Hänsel & Gretel");
    tests.push_back("Слартибартфаст");

    std::string aName("alice678900");
    std::string bName("bob45678900");
    std::string cName("charlie8900");


    auto alice = _makeParticipant(aName);
    participants[aName] = alice;

    alice->setRotateKeyCount (5);
    alice->setMessageNumberBeforeSendKey (10);
    alice->addParticipant(bName);

    alice->updateSenderKey();
    activeParticipants.add(aName);

    auto bob = _makeParticipant(bName);
    participants[bName] = bob;
    bob->setRotateKeyCount (10);
    bob->setMessageNumberBeforeSendKey (5);
    bob->addParticipant(aName);
    bob->updateSenderKey();
    activeParticipants.add(bName);

    auto charlie = _makeParticipant(cName);
    charlie->setRotateKeyCount (10);
    charlie->setMessageNumberBeforeSendKey (5);
    charlie->updateSenderKey();

    std::string sent;
    std::string sender;
    std::string message("Tēnā koe");
    sender = aName;
    sent = participants[sender]->encryptTo(message, bName);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    participants[cName] = charlie;

    // Bob replies.
    sender = bName;
    message = std::string("Kia ora");
    sent = participants[sender]->encryptTo(message, aName);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    // Alice adds Charlie.
    sender = aName;
    Strongvelopens::StringSet inParticipants;
    Strongvelopens::StringSet exParticipants;
    inParticipants.add(cName);

    sent = participants[sender]->alterParticipants(inParticipants, exParticipants);
    activeParticipants.add(cName);
    _checkReceivers(sent, sender, std::string(), participants, activeParticipants);


    // Bob sends to the group.
    sender = bName;
    message = std::string("Good to see you, bro.");
    sent = participants[sender]->encryptTo(message);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    // Alice removes Bob from the chat.
    sender = aName;
    inParticipants.clear();
    exParticipants.add(bName);

    sent = participants[sender]->alterParticipants(inParticipants, exParticipants);
    activeParticipants.remove(bName);
    _checkReceivers(sent, sender, std::string(), participants, activeParticipants);

    // Charlie sends to the group.
    sender = cName;
    message = std::string("Howdy partners!");
    sent = participants[sender]->encryptTo(message);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    // Let's remove Bob's handler, and send another message.
    participants.erase(bName);
    delete bob;
    sender = aName;
    message = std::string("Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn");
    sent = participants[sender]->encryptTo(message);
    _checkReceivers(sent, sender, message, participants, activeParticipants);


    auto bob2 = _makeParticipant(bName);
    participants[bName] = bob2;
    bob2->setRotateKeyCount (10);
    bob2->setMessageNumberBeforeSendKey(5);
    //bob2->keyId = TEST_KEY_ID;
    bob2->addParticipant(aName);
    //bob2->updateSenderKey();

    inParticipants.clear();
    exParticipants.clear();
    inParticipants.add(bName);
    sender = aName;
    bool seedRet = bob2->seed(_messageBuffer);
    message = std::string("Welcome back, mate.");
    sent = participants[sender]->alterParticipants(inParticipants, exParticipants, message);
    activeParticipants.add(bName);

    _checkReceivers(sent, sender, message, participants, activeParticipants);
    EXPECT_EQ(true, seedRet);

    // Chatty Charlie sends to the group.
    sender = cName;
    for (int i = 0; i < tests.size(); i++)
    {
        message = tests[i];
        sent = participants[sender]->encryptTo(message);
        _checkReceivers(sent, sender, message, participants, activeParticipants);
    }
}

TEST(STRONGVELOPE_PROTOCOL_TEST, group_chat_with_chatkeys_RSA)
{
	_messageBuffer.clear();
    std::vector<std::string> RSA_PUB_KEY;
    RSA_PUB_KEY.push_back(Strongvelopens::base64_decode(std::string("wT+JSBnBNjgalMGT5hmFHd/N5eyncAA+w1TzFC4PYfB")
            + std::string("nbX1CFcx6E7BuB0SqgxbJw3ZsvvowsjRvuo8SNtfmVIz4fZV45pBPxCkeCWonN/")
            + std::string("zZZiT3LnYnk1BfnfxfoXtEYRrdVPXAC/VDc9cgy29OXKuuNsREKznb9JFYQUVH9")
            + std::string("FM=")));
    RSA_PUB_KEY.push_back(Strongvelopens::base64_decode(std::string("AQAB")));

    std::vector<std::string> RSA_PRIV_KEY;
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("wT+JSBnBNjgalMGT5hmFHd/N5eyncAA+w1TzFC4PYfB")
            + std::string("nbX1CFcx6E7BuB0SqgxbJw3ZsvvowsjRvuo8SNtfmVIz4fZV45pBPxCkeCWonN/")
            + std::string("zZZiT3LnYnk1BfnfxfoXtEYRrdVPXAC/VDc9cgy29OXKuuNsREKznb9JFYQUVH9")
            + std::string("FM=")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("AQAB")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("B1SXqop/j8T1DSuCprnVGNsCfnRJra/0sYgpaFyO7NI")
            + std::string("nujmEJjuJbfHFWrU6GprksGtvmJb4/emLS3Jd6IKsE/wRthTLLMgbzGm5rRZ92g")
            + std::string("k8XGY3dUrNDsnphFsbIkTVl8n2PX6gdr2hn+rc2zvRupAYkV/smBZX+3pDAcuHo")
            + std::string("+E=")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("7y+NkdfNlnENazteobZ2K0IU7+Mp59BgmrhBl0TvhiA")
            + std::string("5HkI9WJDIZK67NsDa9QNdJ/NCfmqE/eNkZqFLVq0c+w==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("ztVHfgrLnINsPFTjMmjgZM6M39QEUsi4erg4s2tJiuI")
            + std::string("v29szH1n2HdPKFRIUPnemj48kANvp5XagAAhOb8u2iQ==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("IniC+aLVUTonye17fOjT7PYQGGZvsqX4VjP51/gqYPU")
            + std::string("h5jd7qdjr2H7KImD27Vq3wTswuRFW61QrMxNJzUsTow==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("TeoqNGD8sskPTOrta1/2qALnLqo/tq/GTvR255/S5G6")
            + std::string("weLHqYDUTcckGp0lYNu/73ridZ3VwdvBo9ZorchHbgQ==")));
    RSA_PRIV_KEY.push_back(Strongvelopens::base64_decode(std::string("JhqTYTqT5Dj6YoWHWNHbOz24NmMZUXwDms/MDOBM0Nc")
            + std::string("0nX6NjLDooFrJZtBMGMgcSQJd4rULuH94+szNGc2GAg==")));

    std::string word("Hello, World");
    std::string rsa = Strongvelopens::rsaEncryptString(word, RSA_PUB_KEY);
    std::string dersa = Strongvelopens::rsaDecryptString(rsa, RSA_PRIV_KEY);
    EXPECT_EQ(word, dersa);

	std::map<std::string, Strongvelopens::Strongvelope::ProtocolHandler*> participants;
	Strongvelopens::StringSet activeParticipants;

    /*std::string handle("me3456789xw");
    std::string yourkey("you456789xw");
    std::string otherkey("other6789xw");
    std::string keyId("AI");
    std::string preKeyId("AI");

    keyId += (char)0;
    keyId += (char)0;
    preKeyId += (char)0;
    preKeyId += (char)1;*/

    std::vector<std::string> tests;
    tests.push_back("");
    tests.push_back("Don't panic!");
    tests.push_back("Flying Spaghetti Monster");
    tests.push_back("Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn");
    tests.push_back("Tēnā koe");
    tests.push_back("Hänsel & Gretel");
    tests.push_back("Слартибартфаст");

    std::string aName("alice678900");
    std::string bName("bob45678900");
    std::string cName("charlie8900");


    auto alice = _makeParticipant(aName);
    participants[aName] = alice;

    //alice->setMyPrivEd25519 (ED25519_PRIV_KEY);
    //alice->setMyPubEd25519  (ED25519_PUB_KEY);
    //alice->setMyPrivCu25519 (CU25519_PRIV_KEY);
    alice->setRotateKeyCount (5);
    alice->setMessageNumberBeforeSendKey (10);
    alice->addParticipant(bName);
    alice->updateSenderKey();
    activeParticipants.add(aName);

    auto bob = _makeParticipant(bName);
    participants[bName] = bob;
    bob->setMyPrivEd25519 (ED25519_PRIV_KEY);
    bob->setMyPubEd25519  (ED25519_PUB_KEY);
    bob->setMyPrivCu25519 (CU25519_PRIV_KEY);
    bob->setRotateKeyCount (10);
    bob->setMessageNumberBeforeSendKey (5);
    bob->addParticipant(aName);
    bob->updateSenderKey();
    activeParticipants.add(bName);

    auto charlie = _makeParticipant(cName);
    participants[cName] = charlie;
    charlie->setMyPrivEd25519 (ED25519_PRIV_KEY);
    charlie->setMyPubEd25519 (ED25519_PUB_KEY);
    charlie->setMyPrivCu25519 (CU25519_PRIV_KEY);
    charlie->setRotateKeyCount (10);
    charlie->setMessageNumberBeforeSendKey (5);
    charlie->updateSenderKey();

    std::string sent;
    std::string sender;
    std::string message("Tēnā koe");
    sender = aName;
    sent = participants[sender]->encryptTo(message, bName);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    // Bob replies.
    sender = bName;
    message = std::string("Kia ora");
    sent = participants[sender]->encryptTo(message, aName);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    // Alice adds Charlie.
    /*sender = aName;
    Strongvelopens::StringSet inParticipants;
    Strongvelopens::StringSet exParticipants;
    inParticipants.add(cName);
    sent = participants[sender]->alterParticipants(inParticipants, exParticipants);
    activeParticipants.add(cName);

    _checkReceivers(sent, sender, std::string(), participants, activeParticipants);


    // Bob sends to the group.
    sender = bName;
    message = std::string("Good to see you, bro.");
    sent = participants[sender]->encryptTo(message);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    // Alice removes Bob from the chat.
    sender = aName;
    inParticipants.clear();
    exParticipants.add(bName);

    sent = participants[sender]->alterParticipants(inParticipants, exParticipants);
    activeParticipants.remove(bName);
    _checkReceivers(sent, sender, std::string(), participants, activeParticipants);

    // Charlie sends to the group.
    sender = cName;
    message = std::string("Howdy partners!");
    sent = participants[sender]->encryptTo(message);
    _checkReceivers(sent, sender, message, participants, activeParticipants);

    // Let's remove Bob's handler, and send another message.
    participants.erase(bName);
    delete bob;
    sender = aName;
    message = std::string("Ph'nglui mglw'nafh Cthulhu R'lyeh wgah'nagl fhtagn");
    sent = participants[sender]->encryptTo(message);
    _checkReceivers(sent, sender, message, participants, activeParticipants);


    auto bob2 = _makeParticipant(bName);
    participants[bName] = bob2;
    bob2->setMyPrivEd25519 (ED25519_PRIV_KEY);
    bob2->setMyPubEd25519  (ED25519_PUB_KEY);
    bob2->setMyPrivCu25519 (CU25519_PRIV_KEY);
    bob2->setRotateKeyCount (10);
    bob2->setMessageNumberBeforeSendKey (5);
    //bob2->keyId = TEST_KEY_ID;
    bob2->addParticipant(aName);
    //bob2->updateSenderKey();

    inParticipants.clear();
    exParticipants.clear();
    inParticipants.add(bName);
    sender = aName;
    bool seedRet = bob2->seed(_messageBuffer);
    message = std::string("Welcome back, mate.");
    sent = participants[sender]->alterParticipants(inParticipants, exParticipants, message);
    activeParticipants.add(bName);*/

}

int main(int argc, char **argv)
{

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif __TEST

