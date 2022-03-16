#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Mar 15 22:31:25 2022

@author: ga
"""
from Crypto.Cipher import AES
from Crypto.Cipher import Blowfish
from base64 import b64encode

#blowfish, 128 bit in, 32 bit out 
def A3(plainText_byte,k):
    blowfishChallenge= Blowfish.new(k, Blowfish.MODE_ECB) # only one bloc
    # concatenate to 8bytes
    plainConc = bytearray(8)
    for i in range(0,8):
            plainConc[i]=plainText_byte[i]^plainText_byte[i+8]
            
    cypher=blowfishChallenge.encrypt(plainConc);
    # concatenate to 4bytes
    plainText_byte = bytearray(4)
    for i in range(0,4):
            plainText_byte[i]=cypher[i]^cypher[i+4]
    return plainText_byte

#AES, 128bits in, 64 bits out
def A8(plaintText_byte, k):
    aesKc= AES.new(k, AES.MODE_ECB) # only one bloc
    cypher=aesKc.encrypt(plaintText_byte); 
    kc_byte= bytearray(8)
    for i in range(0,8):
        kc_byte[i]=cypher[i]^ cypher[i+8]
    return kc_byte

#decrypt blowfish, stream, CTR, nonce 4byte
def A5_dec(cypher_byte,k,nonce):
    blowfishCom = Blowfish.new(k,Blowfish.MODE_CTR , nonce=nonce)     
    #3. decrypt
    data=blowfishCom.decrypt(cypher_byte);
    return data.decode();

#decrypt blowfish, stream, CTR, nonce 4bytes
def A5_enc(plainText,k,nonce):
    blowfishCom = Blowfish.new(k,Blowfish.MODE_CTR , nonce=nonce)   
    cypher_byte = blowfishCom.encrypt(bytes(plainText,'utf-8'))
    return  cypher_byte


    

 
    